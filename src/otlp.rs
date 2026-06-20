//! OTLP(OpenTelemetry) 트레이스 내보내기 + Server-Timing 헤더 파싱.
//!
//! 담당 기능:
//! - ㊲ 프로브 1건을 OTLP/HTTP(JSON)로 트레이스 백엔드에 전송 + 서버의 Server-Timing 파싱.
//!
//! ## parse_server_timing(headers) -> Vec<(String, Option<f64>)>   (순수)
//! 응답 헤더에서 `Server-Timing`을 찾아(헤더 키 대소문자 무시) 파싱한다.
//! 형식: `name;dur=123.4, db;dur=36, cache, app;desc="x";dur=7`
//! - 콤마로 엔트리 분리, 각 엔트리의 첫 토큰이 metric name.
//! - `dur=<ms>` 파라미터가 있으면 f64로, 없으면 None.
//! - desc 등 다른 파라미터는 무시. 같은 헤더가 여러 줄이면 모두 합친다.
//!
//! 반환은 (name, Option<dur_ms>) 목록(헤더 등장 순서 유지).
//!
//! ## make_traceparent() -> String   (rand 없이 결정적-ish)
//! W3C traceparent: `00-<32 hex trace-id>-<16 hex span-id>-01`.
//! - 난수 의존성 없이 생성: std::process::id() + 프로세스 정적 AtomicU64 카운터(fetch_add) +
//!   현재 시각(나노/밀리, SystemTime)을 섞어 16바이트 trace-id, 8바이트 span-id를 만든다.
//! - 16진수 소문자, trace-id 32자리, span-id 16자리, flags=01(sampled).
//! - all-zero는 유효하지 않으므로 최소 1비트는 세팅되도록 한다.
//!
//! ## export_otlp(result, endpoint) -> Result<()>   (best-effort 네트워크)
//! 프로브 1건을 OTLP/HTTP JSON으로 `{endpoint}/v1/traces`에 POST한다.
//! - Content-Type: application/json. 바디는 serde_json::json! 로 ResourceSpans 구조를 만든다:
//!   resourceSpans[0].scopeSpans[0].spans 에 **단계별 span**을 하나씩
//!   (dns/tcp/tls/ttfb/download) — final_hop()/summed_timings() 기준.
//!   - 각 span: traceId(공통, make_traceparent의 trace-id 재사용 가능), 고유 spanId,
//!     name(예 "dns"), startTimeUnixNano/endTimeUnixNano.
//!   - 타임스탬프: result.timestamp(UTC)를 epoch nanos로 변환한 값을 시작점으로 하고,
//!     단계 누적 오프셋(ms→nanos)을 더해 각 span의 start/end를 만든다.
//!   - 상태(status)·HTTP 버전 등은 span attributes로 넣으면 유용(선택).
//! - 전송은 update/http.rs의 최소 hyper 클라이언트 패턴을 따른다(POST + 바디).
//!   endpoint가 https면 update::http 패턴 그대로, http면 http1 평문 연결.
//! - **best-effort**: 실패하면 에러를 반환하되(혹은 로그) 프로브 흐름을 막지 않는다.
//!   (lib.rs 호출처에서 결과를 무시/경고 처리한다.)
//!
//! ## 구현 메모
//! - 패닉 금지. 모든 fallible 경로는 Result/Option.
//! - epoch nanos 변환은 chrono의 timestamp_nanos_opt() 등 사용(None이면 0 폴백).
//! - #[cfg(test)]로 parse_server_timing(여러 케이스)과 make_traceparent 형식(정규식 없이
//!   길이/구분자/16진수 검사)을 검증 권장.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow};
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::types::{HopResult, PhaseTimings, ProbeResult};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESP_BYTES: usize = 64 * 1024;
const USER_AGENT: &str = concat!("httprove/", env!("CARGO_PKG_VERSION"), " (otlp)");

/// 프로세스 전역 span-id/trace-id 엔트로피 카운터.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 응답 헤더의 Server-Timing을 (name, Option<dur_ms>) 목록으로 파싱한다.
/// --otlp 단발 출력에서 서버측 분해 시간을 노출하는 데 쓰인다.
pub fn parse_server_timing(headers: &[(String, String)]) -> Vec<(String, Option<f64>)> {
    let mut out = Vec::new();
    // 헤더 키는 대소문자 무시. 같은 헤더가 여러 줄이면 모두 누적한다.
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("server-timing") {
            continue;
        }
        // 콤마로 엔트리 분리.
        for entry in value.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // 세미콜론으로 파라미터 분리. 첫 토큰이 metric name.
            let mut parts = entry.split(';');
            let metric = match parts.next() {
                Some(m) => m.trim(),
                None => continue,
            };
            if metric.is_empty() {
                continue;
            }
            // dur=<ms> 파라미터 탐색 (대소문자 무시).
            let mut dur = None;
            for param in parts {
                let param = param.trim();
                if let Some((key, val)) = param.split_once('=')
                    && key.trim().eq_ignore_ascii_case("dur")
                {
                    // 값에 따옴표가 있으면 제거 후 파싱.
                    let val = val.trim().trim_matches('"');
                    dur = val.parse::<f64>().ok();
                }
            }
            out.push((metric.to_string(), dur));
        }
    }
    out
}

/// W3C traceparent 문자열 생성 (rand 없이 pid+카운터+시각 기반).
pub fn make_traceparent() -> String {
    let (trace_id, span_id) = new_ids();
    let trace_hex = hex16(&trace_id);
    let span_hex = hex16(&span_id);
    format!("00-{trace_hex}-{span_hex}-01")
}

/// 새 trace-id 하나를 32 hex로 생성한다. --traceparent와 OTLP export가 같은 trace-id를
/// 공유하도록, 호출처에서 한 번 만들어 헤더(make_traceparent_from)와 export 양쪽에 넘긴다.
pub fn new_trace_id_hex() -> String {
    let (trace_id, _) = new_ids();
    hex16(&trace_id)
}

/// 주어진 trace-id(32 hex)로 W3C traceparent를 만든다. span-id는 새로 만든다.
/// trace-id가 32 hex가 아니면(방어적) 자체 trace-id로 폴백한다.
pub fn make_traceparent_from(trace_hex: &str) -> String {
    if trace_hex.len() != 32 || !trace_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return make_traceparent();
    }
    let span_hex = new_span_id();
    format!("00-{trace_hex}-{span_hex}-01")
}

/// 16바이트 trace-id + 8바이트 span-id를 pid/카운터/시각을 섞어 생성한다.
/// rand 의존성 없이, all-zero를 피하도록 보정한다.
fn new_ids() -> ([u8; 16], [u8; 8]) {
    let pid = std::process::id() as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // 16바이트 trace-id: 시각 ^ (pid<<32) 와 seq 를 섞은 두 워드를 SHA-256으로 확산.
    let mut seed = Vec::with_capacity(32);
    seed.extend_from_slice(&nanos.to_be_bytes());
    seed.extend_from_slice(&pid.to_be_bytes());
    seed.extend_from_slice(&seq.to_be_bytes());
    seed.extend_from_slice(&nanos.rotate_left(17).to_be_bytes());
    let digest = crate::hash::sha256_hex(&seed);
    let bytes = hex_to_bytes(&digest);

    // SHA-256은 32바이트이므로 충분하지만, 방어적으로 길이를 확인하고 채운다.
    let mut trace_id = [0u8; 16];
    let mut span_id = [0u8; 8];
    let n_trace = bytes.len().min(16);
    trace_id[..n_trace].copy_from_slice(&bytes[..n_trace]);
    if bytes.len() > 16 {
        let n_span = (bytes.len() - 16).min(8);
        span_id[..n_span].copy_from_slice(&bytes[16..16 + n_span]);
    }

    // all-zero 방지 — 최소 1비트 보장.
    if trace_id.iter().all(|&b| b == 0) {
        trace_id[15] = 1;
    }
    if span_id.iter().all(|&b| b == 0) {
        span_id[7] = 1;
    }
    (trace_id, span_id)
}

/// hex 문자열을 바이트로 (짝수 자리만, 잘못된 문자는 0).
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::with_capacity(chars.len() / 2);
    let mut i = 0;
    while i + 1 < chars.len() {
        let hi = chars[i].to_digit(16).unwrap_or(0) as u8;
        let lo = chars[i + 1].to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// 임의 길이 바이트를 소문자 hex 문자열로.
fn hex16(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// 새 span-id(8바이트) 하나를 hex 16자리로.
fn new_span_id() -> String {
    let (_, span_id) = new_ids();
    hex16(&span_id)
}

/// 프로브 1건을 OTLP/HTTP JSON으로 {endpoint}/v1/traces 에 POST한다 (best-effort).
///
/// `trace_id`가 Some이면(= --traceparent로 주입한 trace-id) 내보낸 스팬에 그대로 써서,
/// 서버가 W3C 전파로 본 trace와 httprove가 보낸 trace가 백엔드에서 상관되게 한다.
/// None이면 자체 trace-id를 만든다. 어느 경우든 각 span은 고유 span-id를 갖는다.
pub async fn export_otlp(
    result: &ProbeResult,
    endpoint: &str,
    trace_id: Option<&str>,
) -> anyhow::Result<()> {
    let trace_hex = match trace_id {
        Some(t) if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) => t.to_string(),
        _ => new_trace_id_hex(),
    };

    let body = build_payload(result, &trace_hex);
    let payload = serde_json::to_vec(&body).context("serialize OTLP payload")?;

    let url = build_traces_url(endpoint);
    post_json(&url, payload).await
}

/// {endpoint}/v1/traces URL을 만든다 (이미 v1/traces로 끝나면 그대로).
fn build_traces_url(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

/// ResourceSpans JSON 페이로드를 빌드한다. 단계별 span을 하나씩 만든다.
fn build_payload(result: &ProbeResult, trace_hex: &str) -> Value {
    // 시작점: result.timestamp 를 epoch nanos로. 범위 밖이면 현재 시각, 그것도 실패면 0.
    let base_nanos = result
        .timestamp
        .timestamp_nanos_opt()
        .map(|n| n.max(0) as u64)
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        });

    let timings = result.summed_timings();
    let final_hop = result.final_hop();

    // 단계별 (이름, 소요 ms) 순서대로 누적 오프셋을 쌓아 start/end nanos를 만든다.
    let phases = phase_durations(&timings);
    let mut spans = Vec::new();
    let mut offset_ms = 0.0_f64;
    for (name, dur_ms) in phases {
        let start = base_nanos.saturating_add(ms_to_nanos(offset_ms));
        let end = base_nanos.saturating_add(ms_to_nanos(offset_ms + dur_ms));
        spans.push(make_span(trace_hex, name, start, end, final_hop));
        offset_ms += dur_ms;
    }

    // 단계 span이 하나도 없으면(타이밍 0) 전체를 감싸는 단일 span이라도 둔다.
    if spans.is_empty() {
        let dur_ms = result.total_ms.max(0.0);
        let start = base_nanos;
        let end = base_nanos.saturating_add(ms_to_nanos(dur_ms));
        spans.push(make_span(trace_hex, "probe", start, end, final_hop));
    }

    let target = result.target.clone();

    // resource 속성. 연결 IP는 OTLP 스키마 외 top-level 키 대신 표준 resource 속성으로
    // 넣어, 엄격한 protojson 디코더도 거부하지 않게 한다.
    let mut resource_attrs = vec![
        str_attr("service.name", "httprove"),
        str_attr("http.url", &target),
    ];
    if let Some(ip) = final_hop.map(|h| h.ip.to_string()) {
        resource_attrs.push(str_attr("net.peer.ip", &ip));
    }

    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": resource_attrs,
            },
            "scopeSpans": [{
                "scope": {
                    "name": "httprove",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "spans": spans,
            }]
        }],
    })
}

/// 단계별 (name, dur_ms) 목록. dns/tls는 None이면 건너뛴다.
fn phase_durations(t: &PhaseTimings) -> Vec<(&'static str, f64)> {
    let mut v: Vec<(&'static str, f64)> = Vec::with_capacity(5);
    if let Some(dns) = t.dns_ms {
        v.push(("dns", dns.max(0.0)));
    }
    v.push(("tcp", t.tcp_ms.max(0.0)));
    if let Some(tls) = t.tls_ms {
        v.push(("tls", tls.max(0.0)));
    }
    v.push(("ttfb", t.ttfb_ms.max(0.0)));
    v.push(("download", t.download_ms.max(0.0)));
    v
}

/// 단일 span JSON. SPAN_KIND_CLIENT, attributes에 상태/HTTP 버전.
fn make_span(
    trace_hex: &str,
    name: &str,
    start_nanos: u64,
    end_nanos: u64,
    hop: Option<&HopResult>,
) -> Value {
    let mut attrs = vec![str_attr("phase", name)];
    if let Some(h) = hop {
        attrs.push(int_attr("http.status_code", h.status as i64));
        attrs.push(str_attr("http.flavor", &h.http_version));
        attrs.push(str_attr("net.peer.ip", &h.ip.to_string()));
    }
    json!({
        "traceId": trace_hex,
        "spanId": new_span_id(),
        "name": name,
        "kind": 3, // SPAN_KIND_CLIENT
        "startTimeUnixNano": start_nanos.to_string(),
        "endTimeUnixNano": end_nanos.to_string(),
        "attributes": attrs,
    })
}

/// OTLP attribute (문자열 값).
fn str_attr(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

/// OTLP attribute (정수 값). intValue는 문자열로 직렬화한다(proto JSON 규약).
fn int_attr(key: &str, value: i64) -> Value {
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}

/// ms(f64) → nanos(u64). 음수/NaN/오버플로는 0 또는 포화.
fn ms_to_nanos(ms: f64) -> u64 {
    if !ms.is_finite() || ms <= 0.0 {
        return 0;
    }
    let nanos = ms * 1_000_000.0;
    if nanos >= u64::MAX as f64 {
        u64::MAX
    } else {
        nanos as u64
    }
}

/// JSON 바디를 endpoint에 POST한다. http/https 모두 지원.
/// watch/alert(--on-breach webhook)도 이 헬퍼를 재사용한다.
pub(crate) async fn post_json(url: &str, payload: Vec<u8>) -> anyhow::Result<()> {
    let uri: Uri = url
        .parse()
        .with_context(|| format!("invalid otlp url: {url}"))?;
    let scheme = uri.scheme_str().unwrap_or("http").to_string();
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("otlp url has no host: {url}"))?
        .to_string();
    let is_https = scheme == "https";
    let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/v1/traces")
        .to_string();
    let authority = match (is_https, port) {
        (true, 443) | (false, 80) => host.clone(),
        (_, p) => format!("{host}:{p}"),
    };

    // --- TCP ---
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| anyhow!("connect to {host}:{port} timed out"))?
        .with_context(|| format!("connect to {host}:{port}"))?;
    tcp.set_nodelay(true).ok();

    let req = Request::builder()
        .method("POST")
        .uri(&path)
        .header(http::header::HOST, &authority)
        .header(http::header::USER_AGENT, USER_AGENT)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::CONNECTION, "close")
        .body(Full::<Bytes>::from(payload))
        .context("build otlp request")?;

    // https면 TLS 위에, http면 평문 위에 http1 핸드셰이크. 코드 중복을 피하려
    // 핸드셰이크~응답 처리를 클로저로 공유한다.
    // 타임아웃 래퍼: Ok면 내부 Result, Err(elapsed)면 타임아웃 에러로 평탄화한다.
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        if is_https {
            let connector = TlsConnector::from(tls_config()?);
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| anyhow!("invalid server name {host}: {e}"))?;
            let tls = connector
                .connect(server_name, tcp)
                .await
                .with_context(|| format!("tls handshake with {host}"))?;
            send_and_drain(TokioIo::new(tls), req, &host).await
        } else {
            send_and_drain(TokioIo::new(tcp), req, &host).await
        }
    })
    .await
    .map_err(|_| anyhow!("otlp request to {host} timed out"))?
}

/// http1 핸드셰이크 → 요청 전송 → 상태 확인 → 바디 드레인(상한). 2xx/4xx 모두 OK 취급하되,
/// 연결/전송 실패만 에러. (백엔드가 5xx면 에러로 본다.)
async fn send_and_drain<S>(
    io: TokioIo<S>,
    req: Request<Full<Bytes>>,
    host: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .with_context(|| format!("http handshake with {host}"))?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender
        .send_request(req)
        .await
        .with_context(|| format!("send otlp request to {host}"))?;
    let status = resp.status().as_u16();

    // 바디는 상한까지만 드레인 (메모리 보호). 내용은 사용하지 않는다.
    let mut stream = resp.into_body();
    let mut read = 0usize;
    while let Some(frame) = stream.frame().await {
        let frame = frame.with_context(|| format!("read otlp response from {host}"))?;
        if let Some(data) = frame.data_ref() {
            read += data.len();
            if read > MAX_RESP_BYTES {
                break;
            }
        }
    }

    conn_task.abort();

    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(anyhow!("otlp endpoint {host} returned HTTP {status}"))
    }
}

/// 네이티브 루트 인증서로 만든 rustls ClientConfig (프로세스당 1회 빌드).
fn tls_config() -> anyhow::Result<Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            if loaded.certs.is_empty() {
                return Err("no native root certificates found".to_string());
            }
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
        .map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_entry_with_dur() {
        let h = vec![("Server-Timing".to_string(), "db;dur=53.2".to_string())];
        let got = parse_server_timing(&h);
        assert_eq!(got, vec![("db".to_string(), Some(53.2))]);
    }

    #[test]
    fn parses_multiple_entries_and_no_dur() {
        let h = vec![(
            "server-timing".to_string(),
            "name;dur=123.4, db;dur=36, cache, app;desc=\"x\";dur=7".to_string(),
        )];
        let got = parse_server_timing(&h);
        assert_eq!(
            got,
            vec![
                ("name".to_string(), Some(123.4)),
                ("db".to_string(), Some(36.0)),
                ("cache".to_string(), None),
                ("app".to_string(), Some(7.0)),
            ]
        );
    }

    #[test]
    fn dur_before_desc_is_parsed() {
        let h = vec![(
            "Server-Timing".to_string(),
            "cache;dur=7;desc=\"hit\"".to_string(),
        )];
        let got = parse_server_timing(&h);
        assert_eq!(got, vec![("cache".to_string(), Some(7.0))]);
    }

    #[test]
    fn merges_multiple_header_lines() {
        let h = vec![
            ("Server-Timing".to_string(), "a;dur=1".to_string()),
            ("server-timing".to_string(), "b;dur=2".to_string()),
        ];
        let got = parse_server_timing(&h);
        assert_eq!(
            got,
            vec![("a".to_string(), Some(1.0)), ("b".to_string(), Some(2.0))]
        );
    }

    #[test]
    fn ignores_non_server_timing_headers() {
        let h = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("X-Foo".to_string(), "bar;dur=9".to_string()),
        ];
        let got = parse_server_timing(&h);
        assert!(got.is_empty());
    }

    #[test]
    fn empty_and_whitespace_entries_skipped() {
        let h = vec![("Server-Timing".to_string(), " , db;dur=5 , ".to_string())];
        let got = parse_server_timing(&h);
        assert_eq!(got, vec![("db".to_string(), Some(5.0))]);
    }

    #[test]
    fn bad_dur_value_becomes_none() {
        let h = vec![("Server-Timing".to_string(), "x;dur=abc".to_string())];
        let got = parse_server_timing(&h);
        assert_eq!(got, vec![("x".to_string(), None)]);
    }

    #[test]
    fn traceparent_format_is_valid() {
        let tp = make_traceparent();
        // 00-<32hex>-<16hex>-01
        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(
            parts.len(),
            4,
            "traceparent must have 4 dash-separated parts"
        );
        assert_eq!(parts[0], "00", "version must be 00");
        assert_eq!(parts[1].len(), 32, "trace-id must be 32 hex chars");
        assert_eq!(parts[2].len(), 16, "span-id must be 16 hex chars");
        assert_eq!(parts[3], "01", "flags must be 01");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "trace-id must be hex"
        );
        assert!(
            parts[2].chars().all(|c| c.is_ascii_hexdigit()),
            "span-id must be hex"
        );
        // all-zero trace/span은 무효.
        assert_ne!(parts[1], "0".repeat(32));
        assert_ne!(parts[2], "0".repeat(16));
    }

    #[test]
    fn traceparent_is_lowercase_hex() {
        let tp = make_traceparent();
        assert_eq!(tp, tp.to_lowercase(), "hex must be lowercase");
    }

    #[test]
    fn traceparents_differ_across_calls() {
        let a = make_traceparent();
        let b = make_traceparent();
        // 카운터+시각이 섞이므로 두 호출은 달라야 한다.
        assert_ne!(a, b);
    }

    #[test]
    fn build_traces_url_appends_path() {
        assert_eq!(
            build_traces_url("http://localhost:4318"),
            "http://localhost:4318/v1/traces"
        );
        assert_eq!(
            build_traces_url("http://localhost:4318/"),
            "http://localhost:4318/v1/traces"
        );
        assert_eq!(
            build_traces_url("http://localhost:4318/v1/traces"),
            "http://localhost:4318/v1/traces"
        );
    }

    #[test]
    fn ms_to_nanos_handles_edge_cases() {
        assert_eq!(ms_to_nanos(0.0), 0);
        assert_eq!(ms_to_nanos(-1.0), 0);
        assert_eq!(ms_to_nanos(1.0), 1_000_000);
        // 비유한 값(NaN/Inf)은 안전하게 0으로 떨어진다.
        assert_eq!(ms_to_nanos(f64::NAN), 0);
        assert_eq!(ms_to_nanos(f64::INFINITY), 0);
        // 매우 큰 유한 값은 u64::MAX로 포화된다.
        assert_eq!(ms_to_nanos(f64::MAX), u64::MAX);
    }
}
