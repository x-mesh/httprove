//! `httprove serve` — 들어오는 HTTP 요청 인스펙터 / 에코 서버.
//!
//! API를 디버깅할 때 "클라이언트가 실제로 무엇을 보내는지" 보기 위한 서버다
//! (httpbin·webhook.site·RequestBin 류). 기존 `--listen` 익스포터(요청을 *보내는*
//! 프로브)와 정반대로, 이 모드는 요청을 *받아* 콘솔에 사람이 읽기 좋게 dump한다.
//!
//! ## 동작
//! - `TcpListener`에서 accept → 커넥션마다 hyper `auto::Builder`(http1+http2)로 처리.
//!   `--tls`면 `tokio_rustls`로 핸드셰이크 후 동일 처리(자체서명 인증서 자동 생성).
//! - 요청마다: method/target/headers/body 수집(body는 `--max-body`까지) →
//!   콘솔 컬러 dump(기본) 또는 `--json` NDJSON 한 줄 → `--keep>0`이면 인메모리 보관.
//! - 응답(우선순위): 메타 경로 `/__requests*` → `--respond-body/file` → `--no-echo` →
//!   기본 에코백(요청을 JSON 객체로 되돌림). `--status`/`--delay`/`--respond-*` 적용.
//! - `/__requests`(보관 배열) · `/__requests/{seq}`(단건) 조회 엔드포인트. `/__` 경로는
//!   dump·보관 대상에서 제외(메타 전용).
//! - Ctrl-C로 종료. exporter.rs의 accept 루프(Semaphore 동시상한·backoff·signal) 차용.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use clap::Parser;
use colored::Colorize;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// 요청 헤드/바디 처리 전체 커넥션 타임아웃 대신, 동시 커넥션 상한만 둔다
/// (에코 서버는 느린 클라이언트를 일부러 보고 싶을 수 있어 강제 타임아웃은 두지 않는다).
const MAX_CONNECTIONS: usize = 256;

/// accept 실패(EMFILE 등) 후 재시도 전 대기 (busy-spin 방지). exporter.rs와 동일 취지.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// 기본 바디 수신/표시 상한 (1 MiB).
const DEFAULT_MAX_BODY: usize = 1 << 20;

/// `httprove serve` 옵션.
#[derive(Debug, Parser)]
#[command(
    name = "httprove serve",
    about = "Inspect and echo incoming HTTP requests (a local httpbin/RequestBin)",
    long_about = "Run a server that prints every incoming HTTP request (method, path, \
        headers, body) to the console and, by default, echoes the request back as JSON.\n\n\
        Useful for seeing exactly what a client, frontend, or webhook sender transmits.\n\n  \
        httprove serve :8080                 # bind 0.0.0.0:8080, dump + echo\n  \
        httprove serve --json                # NDJSON, one line per request\n  \
        httprove serve --status 503 --delay 2s  # mock a slow failing endpoint\n  \
        httprove serve --tls-cert cert.pem --tls-key key.pem  # HTTPS\n\n\
        GET /__requests        lists captured requests as JSON\n\
        GET /__requests/<seq>  returns a single captured request"
)]
pub struct ServeArgs {
    /// Address to bind: ":8080" or bare "8080" → 0.0.0.0:8080; "127.0.0.1:8080" as-is.
    /// Omitted → 127.0.0.1:8080 (local only).
    #[arg(value_name = "ADDR")]
    pub addr: Option<String>,

    /// Response status code for every request (default 200)
    #[arg(long, value_name = "CODE")]
    pub status: Option<u16>,

    /// Delay this many seconds before responding (test client timeout/retry)
    #[arg(long, default_value_t = 0.0, value_name = "SECS")]
    pub delay: f64,

    /// Respond with this fixed body instead of echoing the request
    #[arg(long = "respond-body", value_name = "STR")]
    pub respond_body: Option<String>,

    /// Respond with the contents of this file instead of echoing the request
    #[arg(long = "respond-file", value_name = "PATH", conflicts_with = "respond_body")]
    pub respond_file: Option<String>,

    /// Content-Type for the response body
    #[arg(long = "respond-type", value_name = "CT")]
    pub respond_type: Option<String>,

    /// Extra response header "Key: Value" (repeatable)
    #[arg(short = 'H', long = "respond-header", value_name = "HEADER")]
    pub respond_headers: Vec<String>,

    /// Do not echo the request; reply with a short fixed "ok"
    #[arg(long = "no-echo")]
    pub no_echo: bool,

    /// Print each request as one NDJSON line instead of a human dump
    #[arg(long)]
    pub json: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Maximum request body bytes to read/show (excess is truncated)
    #[arg(long = "max-body", default_value_t = DEFAULT_MAX_BODY, value_name = "BYTES")]
    pub max_body: usize,

    /// Keep this many recent requests in memory for GET /__requests (0 = disable)
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub keep: usize,

    /// Serve over HTTPS (requires --tls-cert and --tls-key)
    #[arg(long)]
    pub tls: bool,

    /// PEM certificate chain for HTTPS (enables HTTPS; with --tls-key)
    #[arg(long = "tls-cert", value_name = "PATH", requires = "tls_key")]
    pub tls_cert: Option<String>,

    /// PEM private key for HTTPS (with --tls-cert)
    #[arg(long = "tls-key", value_name = "PATH", requires = "tls_cert")]
    pub tls_key: Option<String>,
}

/// `httprove serve [flags]` 진입점. argv는 "{prog} serve" 합성 인자(프로브 파서 미경유).
pub fn main(argv: &[String]) -> ExitCode {
    let args = match ServeArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            return if e.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    // 색상: --no-color이거나 stdout이 tty가 아니면 끈다 (cli_main과 동일 규칙).
    let color = !args.no_color && std::io::IsTerminal::is_terminal(&std::io::stdout());
    colored::control::set_override(color);

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("httprove serve: failed to start runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run(args)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("httprove serve: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// 커넥션 핸들러가 공유하는 불변 설정 + 보관 store.
struct Shared {
    json: bool,
    max_body: usize,
    keep: usize,
    status: StatusCode,
    delay: Duration,
    /// 고정 응답 바디(--respond-body/--respond-file). Some면 에코백을 대체한다.
    respond_body: Option<Bytes>,
    respond_type: Option<String>,
    /// 검증 완료된 커스텀 응답 헤더.
    respond_headers: Vec<(HeaderName, HeaderValue)>,
    echo: bool,
    store: Mutex<VecDeque<CapturedRequest>>,
    seq: AtomicU64,
}

/// 직렬화되는 요청 표현. NDJSON·/__requests·에코백 응답에 공용으로 쓴다.
#[derive(Debug, Clone, Serialize)]
struct CapturedRequest {
    seq: u64,
    /// 수신 시각 (RFC3339, UTC).
    time: String,
    peer: String,
    method: String,
    /// 요청 타깃(path + query), 예: "/api/users?role=admin".
    target: String,
    query: BTreeMap<String, String>,
    #[serde(rename = "httpVersion")]
    http_version: String,
    /// 수신 순서·중복 보존을 위해 배열로 둔다.
    headers: Vec<(String, String)>,
    /// 바디(UTF-8 lossy). 바이너리면 lossy 문자열 + binary=true.
    body: String,
    #[serde(rename = "bodyBytes")]
    body_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    binary: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

async fn run(args: ServeArgs) -> anyhow::Result<ExitCode> {
    if args.delay < 0.0 || !args.delay.is_finite() {
        bail!("--delay must be a non-negative finite number");
    }
    let status = match args.status {
        Some(c) => StatusCode::from_u16(c).with_context(|| format!("invalid --status: {c}"))?,
        None => StatusCode::OK,
    };
    let addr = parse_addr(args.addr.as_deref())?;

    // 고정 응답 바디를 미리 로드(요청마다 파일을 읽지 않는다).
    let respond_body = match (&args.respond_body, &args.respond_file) {
        (Some(s), _) => Some(Bytes::from(s.clone().into_bytes())),
        (None, Some(path)) => Some(Bytes::from(
            fs::read(path).with_context(|| format!("failed to read --respond-file: {path}"))?,
        )),
        (None, None) => None,
    };

    // 커스텀 응답 헤더를 미리 검증/변환.
    let mut respond_headers = Vec::with_capacity(args.respond_headers.len());
    for h in &args.respond_headers {
        let (k, v) = h
            .split_once(':')
            .with_context(|| format!("invalid --respond-header (expected \"Key: Value\"): {h}"))?;
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .with_context(|| format!("invalid response header name: {k}"))?;
        let val = HeaderValue::from_str(v.trim())
            .with_context(|| format!("invalid response header value: {v}"))?;
        respond_headers.push((name, val));
    }

    let tls = if args.tls || args.tls_cert.is_some() {
        Some(build_tls_acceptor(&args)?)
    } else {
        None
    };

    let shared = Arc::new(Shared {
        json: args.json,
        max_body: args.max_body,
        keep: args.keep,
        status,
        delay: Duration::from_secs_f64(args.delay),
        respond_body,
        respond_type: args.respond_type.clone(),
        respond_headers,
        echo: !args.no_echo,
        store: Mutex::new(VecDeque::new()),
        seq: AtomicU64::new(1),
    });

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    let local = listener.local_addr().unwrap_or(addr);
    let scheme = if tls.is_some() { "https" } else { "http" };
    eprintln!("listening on {scheme}://{local}  (Ctrl-C to stop)");

    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => match Arc::clone(&conn_limit).try_acquire_owned() {
                    Ok(permit) => {
                        let shared = Arc::clone(&shared);
                        let tls = tls.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            match tls {
                                // TLS 핸드셰이크 실패(평문 접속 등)는 조용히 닫는다.
                                Some(acceptor) => {
                                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                                        serve_conn(TokioIo::new(tls_stream), shared, peer).await;
                                    }
                                }
                                None => serve_conn(TokioIo::new(stream), shared, peer).await,
                            }
                        });
                    }
                    // 동시 상한 초과: 응답 없이 즉시 닫는다.
                    Err(_) => drop(stream),
                },
                Err(e) => {
                    eprintln!("httprove serve: accept error: {e}");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// 한 커넥션을 hyper auto(http1+http2)로 처리한다. TCP/TLS 스트림 모두 받는다.
async fn serve_conn<I>(io: TokioIo<I>, shared: Arc<Shared>, peer: SocketAddr)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req: Request<Incoming>| {
        let shared = Arc::clone(&shared);
        handle(req, shared, peer)
    });
    // keep-alive로 여러 요청을 처리. 커넥션 오류(클라이언트 단절 등)는 무시한다.
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}

/// 요청 1개 처리: 수집 → 출력/보관 → 응답.
async fn handle(
    req: Request<Incoming>,
    shared: Arc<Shared>,
    peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();

    // 메타 엔드포인트(/__...)는 dump·보관하지 않는다.
    if parts.uri.path().starts_with("/__") {
        return Ok(meta_response(parts.uri.path(), &shared));
    }

    let (data, truncated) = collect_body(body, shared.max_body).await;
    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    let captured = build_captured(seq, &parts, peer, &data, truncated);

    // 출력.
    if shared.json {
        print_ndjson(&captured);
    } else {
        print_dump(&captured, &data);
    }

    // 보관(ring buffer).
    if shared.keep > 0 {
        let mut store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
        store.push_back(captured.clone());
        while store.len() > shared.keep {
            store.pop_front();
        }
    }

    // 지연 mock.
    if !shared.delay.is_zero() {
        tokio::time::sleep(shared.delay).await;
    }

    Ok(build_response(&shared, &captured))
}

/// 바디를 `max`까지 수집한다. 초과하면 거기서 끊고 truncated=true.
async fn collect_body(mut body: Incoming, max: usize) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    let mut truncated = false;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(chunk) = frame.into_data() {
                    if data.len() + chunk.len() > max {
                        let take = max.saturating_sub(data.len());
                        data.extend_from_slice(&chunk[..take]);
                        truncated = true;
                        break;
                    }
                    data.extend_from_slice(&chunk);
                }
            }
            Some(Err(_)) => break, // 수신 오류 — 받은 만큼으로 진행.
            None => break,
        }
    }
    (data, truncated)
}

/// parts + 수집한 바디로 직렬화용 CapturedRequest를 만든다.
fn build_captured(
    seq: u64,
    parts: &hyper::http::request::Parts,
    peer: SocketAddr,
    data: &[u8],
    truncated: bool,
) -> CapturedRequest {
    let target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());

    let query = parts
        .uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .collect::<BTreeMap<String, String>>()
        })
        .unwrap_or_default();

    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();

    let binary = std::str::from_utf8(data).is_err();
    let body = String::from_utf8_lossy(data).into_owned();

    CapturedRequest {
        seq,
        time: chrono::Utc::now().to_rfc3339(),
        peer: peer.to_string(),
        method: parts.method.as_str().to_string(),
        target,
        query,
        http_version: format!("{:?}", parts.version),
        headers,
        body,
        body_bytes: data.len(),
        truncated,
        binary,
    }
}

/// `/__requests`(보관 배열) · `/__requests/{seq}`(단건) 응답. 그 외 `/__`는 404.
fn meta_response(path: &str, shared: &Shared) -> Response<Full<Bytes>> {
    let store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
    if path == "/__requests" {
        let body = serde_json::to_vec_pretty(&Vec::from_iter(store.iter())).unwrap_or_default();
        return json_response(StatusCode::OK, Bytes::from(body));
    }
    if let Some(rest) = path.strip_prefix("/__requests/")
        && let Ok(want) = rest.parse::<u64>()
        && let Some(found) = store.iter().find(|r| r.seq == want)
    {
        let body = serde_json::to_vec_pretty(found).unwrap_or_default();
        return json_response(StatusCode::OK, Bytes::from(body));
    }
    json_response(
        StatusCode::NOT_FOUND,
        Bytes::from_static(b"{\"error\":\"not found\"}\n"),
    )
}

/// 우선순위에 따라 응답을 만든다: respond-body/file → no-echo → 에코백.
fn build_response(shared: &Shared, captured: &CapturedRequest) -> Response<Full<Bytes>> {
    let (default_ct, body): (&str, Bytes) = if let Some(rb) = &shared.respond_body {
        ("text/plain; charset=utf-8", rb.clone())
    } else if !shared.echo {
        ("text/plain; charset=utf-8", Bytes::from_static(b"ok\n"))
    } else {
        let json = serde_json::to_vec_pretty(captured).unwrap_or_default();
        ("application/json", Bytes::from(json))
    };
    let ct = shared.respond_type.as_deref().unwrap_or(default_ct);

    let mut builder = Response::builder()
        .status(shared.status)
        .header(hyper::header::CONTENT_TYPE, ct);
    for (name, val) in &shared.respond_headers {
        builder = builder.header(name, val);
    }
    // 헤더는 모두 사전 검증되었고 status/ct도 유효 → build 실패는 발생하지 않는다.
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b""))))
}

fn json_response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b""))))
}

// === 주소 파싱 ============================================================

/// ":8080"/"8080" → 0.0.0.0:8080, None → 127.0.0.1:8080, "host:port"는 그대로.
/// "localhost"는 127.0.0.1로 치환한다.
fn parse_addr(arg: Option<&str>) -> anyhow::Result<SocketAddr> {
    let raw = match arg {
        None => return Ok(SocketAddr::from(([127, 0, 0, 1], 8080))),
        Some(s) => s.trim(),
    };
    let candidate = if let Some(port) = raw.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else if raw.chars().all(|c| c.is_ascii_digit()) {
        format!("0.0.0.0:{raw}")
    } else if let Some(port) = raw.strip_prefix("localhost:") {
        format!("127.0.0.1:{port}")
    } else {
        raw.to_string()
    };
    candidate
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid bind address: {raw} (use IP:PORT, :PORT, or PORT)"))
}

// === TLS ==================================================================

/// 설치된 기본 provider를 쓰고, 없으면 ring 기본값을 사용한다 (probe.rs와 동일 규칙).
fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

fn build_tls_acceptor(args: &ServeArgs) -> anyhow::Result<TlsAcceptor> {
    // 자동 자체서명은 rcgen이 ratatui가 강제하는 time(parsing)과 E0119로 충돌해 채택하지 못했다.
    // HTTPS는 사용자가 cert/key를 제공할 때만 켠다 (openssl 한 줄로 만들 수 있다).
    let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) else {
        bail!(
            "--tls needs a certificate. Generate a self-signed one:\n  \
             openssl req -x509 -newkey rsa:2048 -nodes -days 365 \\\n    \
             -keyout key.pem -out cert.pem -subj '/CN=localhost'\n\
             then run:\n  \
             httprove serve :8443 --tls-cert cert.pem --tls-key key.pem"
        );
    };
    let (certs, key) = load_pem(cert_path, key_path)?;

    let mut config = rustls::ServerConfig::builder_with_provider(default_crypto_provider())
        .with_safe_default_protocol_versions()
        .context("TLS config error")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid certificate/key")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_pem(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file =
        fs::File::open(cert_path).with_context(|| format!("failed to open --tls-cert: {cert_path}"))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse --tls-cert: {cert_path}"))?;
    if certs.is_empty() {
        bail!("no certificates found in --tls-cert: {cert_path}");
    }
    let key_file =
        fs::File::open(key_path).with_context(|| format!("failed to open --tls-key: {key_path}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .with_context(|| format!("failed to parse --tls-key: {key_path}"))?
        .with_context(|| format!("no private key found in --tls-key: {key_path}"))?;
    Ok((certs, key))
}

// === 출력 =================================================================

/// 요청을 한 줄 NDJSON으로 stdout에 출력한다.
fn print_ndjson(captured: &CapturedRequest) {
    if let Ok(line) = serde_json::to_string(captured) {
        println!("{line}");
    }
}

/// 요청을 사람이 읽기 좋게 콘솔에 dump한다 (색상은 colored 전역 override를 따른다).
fn print_dump(captured: &CapturedRequest, data: &[u8]) {
    let sep = "─".repeat(63);
    println!(
        "{}",
        format!("┌─ #{} {}  from {}", captured.seq, captured.time, captured.peer)
            .dimmed()
    );
    println!(
        "{} {}  {}",
        captured.method.bold().cyan(),
        captured.target.bold(),
        captured.http_version.dimmed()
    );
    for (k, v) in &captured.headers {
        println!("{}: {v}", k.dimmed());
    }

    if captured.body_bytes > 0 {
        println!();
        render_body(captured, data);
    }
    println!("{}", format!("└{sep}").dimmed());
}

/// 바디를 Content-Type/내용에 맞춰 렌더링한다.
fn render_body(captured: &CapturedRequest, data: &[u8]) {
    let ctype = captured
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if captured.binary {
        println!("{}", hexdump(data));
    } else if ctype.contains("json")
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(data)
        && let Ok(pretty) = serde_json::to_string_pretty(&value)
    {
        println!("{pretty}");
    } else {
        // 텍스트 바디 그대로 (lossy 문자열).
        print!("{}", captured.body);
        if !captured.body.ends_with('\n') {
            println!();
        }
    }
    if captured.truncated {
        println!(
            "{}",
            format!("  … truncated at {} bytes", captured.body_bytes).dimmed()
        );
    }
}

/// 바이너리 바디의 hexdump (최대 512바이트). `오프셋  hex…  |ascii|`.
fn hexdump(data: &[u8]) -> String {
    const MAX: usize = 512;
    let slice = &data[..data.len().min(MAX)];
    let mut out = String::new();
    for (i, chunk) in slice.chunks(16).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str(&format!("{:08x}  {:<49} |{}|\n", i * 16, hex, ascii));
    }
    if data.len() > MAX {
        out.push_str(&format!("  … {} more bytes\n", data.len() - MAX));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_variants() {
        assert_eq!(
            parse_addr(None).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 8080))
        );
        assert_eq!(
            parse_addr(Some(":9000")).unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 9000))
        );
        assert_eq!(
            parse_addr(Some("8080")).unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 8080))
        );
        assert_eq!(
            parse_addr(Some("127.0.0.1:1234")).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 1234))
        );
        assert_eq!(
            parse_addr(Some("localhost:5555")).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 5555))
        );
        assert!(parse_addr(Some("not-an-addr")).is_err());
    }

    #[test]
    fn hexdump_renders_offsets_and_ascii() {
        let dump = hexdump(b"AB\x00\xff");
        assert!(dump.starts_with("00000000  "));
        assert!(dump.contains("41 42 00 ff"));
        assert!(dump.contains("|AB..|"));
    }
}
