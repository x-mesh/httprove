//! HTTP(S) 프로브 엔진 — httprove의 핵심.
//!
//! 매 프로브마다 새 연결을 직접 수립하여 단계별 시간을 측정한다:
//!
//! 1. DNS      — `tokio::net::lookup_host("host:port")`. `cfg.resolve`가 있거나
//!    URL 호스트가 IP 리터럴이면 생략 (dns_ms = None).
//!    `cfg.ip_family`로 결과를 필터링하고 첫 IP를 사용한다.
//!    해당 패밀리 주소가 없으면 ErrorPhase::Dns 실패.
//! 2. TCP      — `TcpStream::connect((ip, port))` 후 `set_nodelay(true)`.
//! 3. TLS      — https일 때만. tokio-rustls 핸드셰이크 시간을 측정하고
//!    peer cert 체인(DER), TLS 버전, cipher suite, ALPN 결과를 수집.
//! 4. TTFB     — 요청 전송 시작(send_request 호출)부터 응답 헤더 수신까지.
//! 5. Download — 응답 바디를 끝까지 읽는 시간. 바이트 수만 집계하고 내용은 버린다.
//!
//! ## TLS 설정
//! - 루트 인증서: `rustls_native_certs::load_native_certs()` → RootCertStore.
//! - ClientConfig는 (insecure, http_version) 조합별로 OnceLock에 캐시해 프로세스당
//!   1회만 빌드한다. 일회성 빌드 비용(네이티브 루트 저장소 로드, macOS에서 ~100ms)이
//!   측정값에 섞이지 않도록 `probe()`가 타이머 시작 전에 캐시를 워밍한다.
//! - ALPN: `HttpVersionPref::Auto` → ["h2", "http/1.1"], `Http1` → ["http/1.1"].
//! - `cfg.insecure` → 모든 인증서를 수락하는 커스텀 `ServerCertVerifier`
//!   (`rustls::client::danger::ServerCertVerifier`). 이때도 체인은 수집한다.
//! - SNI: URL 호스트 (resolve override여도 URL 호스트 유지). IP 리터럴 호스트면
//!   `ServerName::IpAddress`.
//!
//! ## HTTP 처리
//! - 수립된 (TLS) 스트림을 `hyper_util::rt::TokioIo`로 감싸고,
//!   ALPN 결과가 "h2"면 `hyper::client::conn::http2::handshake`
//!   (executor: `hyper_util::rt::TokioExecutor`), 아니면
//!   `hyper::client::conn::http1::handshake`. conn future는 `tokio::spawn`으로 구동.
//! - 요청 헤더: Host(http1, 비표준 포트면 host:port), User-Agent
//!   `httprove/<CARGO_PKG_VERSION>`, Accept `*/*`, http1이면 `Connection: close`.
//!   `cfg.headers`의 사용자 헤더가 같은 이름의 기본값을 덮어쓴다.
//! - 바디: `cfg.body`가 있으면 Content-Length와 함께 전송 (Full<Bytes> 사용).
//! - 응답 바디는 `http_body_util::BodyExt::frame()` 루프로 읽어 데이터 프레임
//!   바이트 수만 합산한다.
//!
//! ## 리다이렉트
//! - `cfg.max_redirects > 0`이고 응답이 3xx + Location이면 다음 hop으로 진행.
//!   Location은 현재 URL 기준 상대 경로 해석 (`url.join`).
//! - 301/302/303 → 메서드를 GET으로 바꾸고 바디 제거. 307/308 → 메서드/바디 유지.
//! - 한도 초과 시 ErrorPhase::Redirect 실패 (이미 수집한 hops는 보존).
//! - resolve override는 첫 hop에만 적용한다 (리다이렉트 대상은 정상 DNS).
//!
//! ## 타임아웃
//! - `cfg.timeout`은 프로브 전체(모든 hop) 예산. 각 await 지점을 남은 예산으로
//!   `tokio::time::timeout` 감싸고, 초과 시 해당 단계를 `ErrorPhase`로,
//!   `timed_out: true`로 기록한다.
//!
//! ## 실패 처리
//! - 이 함수는 절대 panic하지 않고 모든 실패를 `ProbeResult.error`에 담는다.
//! - 실패 전에 완료된 hop들은 `ProbeResult.hops`에 포함시킨다.
//! - `total_ms`는 프로브 시작부터 종료(성공/실패)까지의 실측 시간.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio::time::Instant as TokioInstant;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::types::{
    CertInfo, ErrorPhase, Expectations, HopResult, HttpVersionPref, IpFamily, PhaseTimings,
    ProbeConfig, ProbeError, ProbeResult, TlsInfo,
};

/// body_contains 어설션용 바디 캡처 상한 (1 MiB).
/// 이보다 큰 바디는 앞부분만 캡처하고, body_bytes 집계는 전체 기준으로 계속한다.
const BODY_CAPTURE_CAP: usize = 1024 * 1024;

/// 프로브 1회 실행. 리다이렉트 추적 포함. 실패는 ProbeResult.error로 보고.
pub async fn probe(cfg: &ProbeConfig, seq: u64) -> ProbeResult {
    // 일회성 TLS 설정 비용(네이티브 루트 저장소 로드 등)이 total_ms에 섞이지 않도록
    // 타이머 시작 전에 캐시를 워밍한다. 첫 프로브에서만 실제 빌드가 일어난다.
    warm_tls_config(cfg);
    let timestamp = chrono::Utc::now();
    let start = Instant::now();
    // 프로브 전체(모든 hop) 공유 데드라인.
    let deadline = TokioInstant::now() + cfg.timeout;

    let mut hops: Vec<HopResult> = Vec::new();
    let mut error: Option<ProbeError> = None;
    // body_contains 어설션용 바디 캡처. 매 hop 덮어쓰므로 루프 종료 시점에는
    // 최종 hop의 캡처만 남는다 (중간 3xx hop의 캡처는 버려짐).
    let mut final_capture: Option<Vec<u8>> = None;

    let mut current_url = cfg.url.clone();
    let mut current_method = cfg.method.clone();
    let mut current_body = cfg.body.clone();
    // 지금까지 따라간 리다이렉트 수 (= 현재 hop 인덱스).
    let mut hop_index: u32 = 0;

    loop {
        // resolve override는 첫 hop에만 적용.
        let resolve = if hop_index == 0 { cfg.resolve } else { None };
        let (mut hop, capture) = match run_hop(
            cfg,
            &current_url,
            &current_method,
            current_body.as_deref(),
            resolve,
            deadline,
        )
        .await
        {
            Ok(pair) => pair,
            Err(fail) => {
                error = Some(fail.into_probe_error());
                break;
            }
        };
        final_capture = capture;

        // 3xx + Location → 절대 URL로 해석해 redirect_to에 기록.
        let status = hop.status;
        let location = if (300..400).contains(&status) {
            find_header(&hop.response_headers, "location")
        } else {
            None
        };

        let mut next_url: Option<Url> = None;
        if let Some(loc) = location {
            match current_url.join(&loc) {
                Ok(joined) => {
                    hop.redirect_to = Some(joined.to_string());
                    next_url = Some(joined);
                }
                // 따라가야 하는데 체인을 해석할 수 없음 → 에러.
                // hop 자체는 완료되었으므로 보존한다.
                Err(e) if cfg.max_redirects > 0 => {
                    hops.push(hop);
                    error = Some(ProbeError {
                        phase: ErrorPhase::Redirect,
                        message: format!("invalid redirect location {loc:?}: {e}"),
                        timed_out: false,
                        hint: None,
                    });
                    break;
                }
                // 리다이렉트를 따라가지 않는 모드(-L 없음): 3xx 자체가 최종 결과이므로
                // 해석 불가 Location은 redirect_to 미기록으로만 처리한다
                // (keep-alive의 resolve_redirect_to와 동일한 관용).
                Err(_) => {}
            }
        }
        hops.push(hop);

        let Some(next) = next_url else {
            break; // 리다이렉트 아님 → 최종 결과.
        };
        if cfg.max_redirects == 0 {
            break; // 따라가지 않음. 3xx 자체가 최종 결과 (성공).
        }
        if hop_index >= cfg.max_redirects {
            error = Some(ProbeError {
                phase: ErrorPhase::Redirect,
                message: "too many redirects".to_string(),
                timed_out: false,
                hint: None,
            });
            break;
        }
        match next.scheme() {
            "http" | "https" => {}
            other => {
                error = Some(ProbeError {
                    phase: ErrorPhase::Redirect,
                    message: format!("unsupported redirect scheme: {other}"),
                    timed_out: false,
                    hint: None,
                });
                break;
            }
        }
        // 301/302/303 → GET + 바디 제거, 307/308 등은 메서드/바디 유지.
        if matches!(status, 301..=303) {
            current_method = "GET".to_string();
            current_body = None;
        }
        current_url = next;
        hop_index += 1;
    }

    let mut result = ProbeResult {
        target: cfg.url.to_string(),
        seq,
        timestamp,
        hops,
        error,
        expect_failures: vec![],
        total_ms: elapsed_ms(start),
    };
    evaluate_expectations(&mut result, &cfg.expect, final_capture.as_deref());
    result
}

/// `--expect-*` 어설션을 평가해 위반 사유를 result.expect_failures에 채운다.
/// 네트워크 실패(error)면 평가하지 않는다.
///
/// 평가 항목:
/// - status: 최종 hop 상태가 허용 목록 중 하나와 match
/// - body_contains: 최종 hop 바디 캡처(`final_body`, 최대 BODY_CAPTURE_CAP)에
///   부분 문자열 포함 (UTF-8 lossy 변환 후 검사)
/// - max_ttfb_ms: summed_timings().ttfb_ms, max_total_ms: result.total_ms
/// - min_cert_days: leaf_cert().not_after 기준으로 평가 시점에 재계산한 잔여 일수
///   (인증서가 없으면 그 자체가 위반)
///
/// 위반 메시지는 영어 한 줄: "status 404 not in [200, 2xx]",
/// "ttfb 812.3ms > 500ms", "cert expires in 5 days < 30" 등.
fn evaluate_expectations(
    result: &mut ProbeResult,
    expect: &Expectations,
    final_body: Option<&[u8]>,
) {
    if expect.is_empty() || result.error.is_some() {
        return;
    }
    let mut failures: Vec<String> = Vec::new();

    if let Some(allowed) = &expect.status
        && let Some(hop) = result.final_hop()
        && !allowed.iter().any(|e| e.matches(hop.status))
    {
        let list = allowed
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        failures.push(format!("status {} not in [{list}]", hop.status));
    }

    if let Some(needle) = &expect.body_contains {
        // 캡처가 없으면(방어적) 빈 바디로 취급한다.
        let body = final_body.unwrap_or(&[]);
        if !String::from_utf8_lossy(body).contains(needle.as_str()) {
            failures.push(format!(
                "body does not contain \"{}\"",
                truncate_display(needle, 40)
            ));
        }
    }

    if let Some(max) = expect.max_ttfb_ms {
        let ttfb = result.summed_timings().ttfb_ms;
        if ttfb > max {
            failures.push(format!("ttfb {ttfb:.1}ms > {max}ms"));
        }
    }

    if let Some(max) = expect.max_total_ms
        && result.total_ms > max
    {
        failures.push(format!("total {:.1}ms > {max}ms", result.total_ms));
    }

    if let Some(min_days) = expect.min_cert_days {
        match result.leaf_cert() {
            Some(cert) => {
                // keep-alive 재사용 hop은 연결 시점의 days_remaining 스냅샷을 복제하므로
                // (오래 살아있는 세션에서는 값이 줄지 않는다) not_after에서 평가 시점
                // 기준으로 다시 계산한다.
                let days_remaining =
                    crate::cert::days_remaining_from(cert.not_after, chrono::Utc::now());
                if days_remaining < min_days {
                    failures.push(format!(
                        "cert expires in {days_remaining} days < {min_days}"
                    ));
                }
            }
            // http 대상 등 인증서를 관측하지 못한 경우 — 검사 불가 자체가 위반.
            None => failures.push("no certificate to check (http target)".to_string()),
        }
    }

    result.expect_failures = failures;
}

/// 어설션 위반 메시지 표시용 문자열 자르기 (문자 단위, 잘리면 "..." 추가).
fn truncate_display(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max_chars).collect();
        t.push_str("...");
        t
    }
}

// ---------------------------------------------------------------------------
// 내부 구현
// ---------------------------------------------------------------------------

/// 단계 실패 정보 (내부용). 종료 시 ProbeError로 변환된다.
struct PhaseFail {
    phase: ErrorPhase,
    message: String,
    timed_out: bool,
    /// 진단 힌트 (TLS 핸드셰이크 디코더 등이 채운다). 기본 None.
    hint: Option<String>,
}

impl PhaseFail {
    fn new(phase: ErrorPhase, message: String) -> Self {
        Self {
            phase,
            message,
            timed_out: false,
            hint: None,
        }
    }

    fn into_probe_error(self) -> ProbeError {
        ProbeError {
            phase: self.phase,
            message: self.message,
            timed_out: self.timed_out,
            hint: self.hint,
        }
    }
}

/// http1 / h2 송신기를 단일 타입으로 다루기 위한 래퍼.
enum HttpSender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl HttpSender {
    /// 연결이 이미 닫혀 더 이상 요청을 보낼 수 없는 상태인지 (h1 EOF / h2 GOAWAY 등
    /// 으로 conn 구동 태스크가 종료된 경우). keep-alive 재사용 가능 여부 판별용.
    fn is_closed(&self) -> bool {
        match self {
            HttpSender::H1(s) => s.is_closed(),
            HttpSender::H2(s) => s.is_closed(),
        }
    }
}

/// drop 시 conn 구동 태스크를 중단시켜 hop 종료 후 태스크 누수를 방지한다.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// future를 공유 데드라인으로 감싼다. 초과 시 해당 단계의 타임아웃 실패를 반환.
async fn phase_await<T, F>(
    deadline: TokioInstant,
    phase: ErrorPhase,
    fut: F,
) -> Result<T, PhaseFail>
where
    F: Future<Output = Result<T, PhaseFail>>,
{
    match tokio::time::timeout_at(deadline, fut).await {
        Ok(result) => result,
        Err(_) => Err(PhaseFail {
            phase,
            message: format!("timed out during {phase} phase"),
            timed_out: true,
            hint: None,
        }),
    }
}

/// 연결 수립 결과: 살아있는 송신기 + 연결 시점 메타데이터/단계 시간.
/// run_hop(요청 후 연결 폐기)과 KeepAliveProber(연결 보관)가 공용으로 사용한다.
struct ConnectedHop {
    sender: HttpSender,
    /// conn 구동 태스크 가드 — drop 시 태스크가 중단되므로 연결 수명 동안 보관한다.
    conn_guard: AbortOnDrop,
    /// 연결 절차 시작 시각 (DNS 직전). hop total_ms 계산용.
    started: Instant,
    ip: IpAddr,
    port: u16,
    local_addr: Option<SocketAddr>,
    resolved_ips: Vec<IpAddr>,
    dns_ms: Option<f64>,
    tcp_ms: f64,
    tls_ms: Option<f64>,
    tls_info: Option<TlsInfo>,
    cert_chain: Vec<CertInfo>,
}

/// hop의 연결 수립 구간: DNS → TCP → (TLS) → HTTP 핸드셰이크.
async fn connect_hop(
    cfg: &ProbeConfig,
    url: &Url,
    resolve: Option<IpAddr>,
    deadline: TokioInstant,
) -> Result<ConnectedHop, PhaseFail> {
    let is_https = match url.scheme() {
        "https" => true,
        "http" => false,
        other => {
            return Err(PhaseFail::new(
                ErrorPhase::Setup,
                format!("unsupported URL scheme: {other}"),
            ));
        }
    };
    let host_str = url
        .host_str()
        .ok_or_else(|| PhaseFail::new(ErrorPhase::Setup, "URL has no host".to_string()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| PhaseFail::new(ErrorPhase::Setup, "URL has no port".to_string()))?;

    // TLS ClientConfig는 hop 타이머 시작 전에 캐시에서 가져온다. 일회성 빌드 비용이
    // hop 측정값에 섞이지 않게 하기 위함이다 (probe()의 워밍으로 보통 이미 빌드됨).
    // is_https일 때만 Some이며, 아래 TLS 분기는 이 Some 여부로 갈라진다.
    let tls_config = if is_https {
        Some(
            cached_tls_config(cfg.insecure, cfg.http_version)
                .map_err(|m| PhaseFail::new(ErrorPhase::Tls, m))?,
        )
    } else {
        None
    };

    let hop_start = Instant::now();

    // --- DNS --------------------------------------------------------------
    // resolve override 또는 IP 리터럴 호스트면 조회를 생략한다 (dns_ms = None).
    let (resolved_ips, dns_ms): (Vec<IpAddr>, Option<f64>) = if let Some(ip) = resolve {
        (vec![ip], None)
    } else {
        match url.host() {
            Some(url::Host::Ipv4(v4)) => (vec![IpAddr::V4(v4)], None),
            Some(url::Host::Ipv6(v6)) => (vec![IpAddr::V6(v6)], None),
            _ => {
                let dns_start = Instant::now();
                let addrs = phase_await(deadline, ErrorPhase::Dns, async {
                    tokio::net::lookup_host(format!("{host_str}:{port}"))
                        .await
                        .map_err(|e| {
                            PhaseFail::new(
                                ErrorPhase::Dns,
                                format!("DNS lookup for {host_str:?} failed: {}", error_chain(&e)),
                            )
                        })
                })
                .await?;
                let dns_ms = elapsed_ms(dns_start);

                // ip_family 필터 + 순서 보존 중복 제거.
                let mut ips: Vec<IpAddr> = Vec::new();
                for addr in addrs {
                    let ip = addr.ip();
                    if family_matches(ip, cfg.ip_family) && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                if ips.is_empty() {
                    let family = match cfg.ip_family {
                        IpFamily::V4 => "IPv4",
                        IpFamily::V6 => "IPv6",
                        IpFamily::Auto => "IP",
                    };
                    return Err(PhaseFail::new(
                        ErrorPhase::Dns,
                        format!("no {family} addresses found for {host_str}"),
                    ));
                }
                (ips, Some(dns_ms))
            }
        }
    };
    let ip = resolved_ips[0]; // 위에서 비어 있지 않음을 보장.

    // --- TCP ----------------------------------------------------------------
    let tcp_start = Instant::now();
    let tcp_stream = phase_await(deadline, ErrorPhase::Tcp, async {
        TcpStream::connect((ip, port)).await.map_err(|e| {
            // SocketAddr 포맷을 써서 IPv6를 [addr]:port로 올바르게 표기한다
            // (그냥 {ip}:{port}면 "2001:...:::443"처럼 콜론이 겹친다).
            PhaseFail::new(
                ErrorPhase::Tcp,
                format!(
                    "connect to {} failed: {}",
                    SocketAddr::new(ip, port),
                    error_chain(&e)
                ),
            )
        })
    })
    .await?;
    let tcp_ms = elapsed_ms(tcp_start);
    let _ = tcp_stream.set_nodelay(true); // 측정 지연 방지. 실패해도 치명적이지 않음.
    let local_addr = tcp_stream.local_addr().ok(); // 소스 IP/포트 (표시용, 실패 무시).

    // --- TLS (https) + HTTP 핸드셰이크 ---------------------------------------
    // 스트림 타입이 분기마다 다르므로 핸드셰이크까지 분기 안에서 끝낸다.
    // tls_config는 is_https일 때만 Some (hop 타이머 시작 전에 획득).
    let (sender, conn_guard, tls_ms, tls_info, cert_chain) = if let Some(tls_config) = tls_config {
        let connector = TlsConnector::from(tls_config);
        // SNI는 항상 URL 호스트 (resolve override여도 유지).
        let sni = sni_server_name(url)?;

        let tls_start = Instant::now();
        let tls_stream = phase_await(deadline, ErrorPhase::Tls, async {
            connector.connect(sni, tcp_stream).await.map_err(|e| {
                let message = format!("TLS handshake failed: {}", error_chain(&e));
                // ㉑ 핸드셰이크 오류 디코더: 사람이 읽을 원인+해법을 hint로 채운다.
                let hint = crate::chain::decode_tls_error(&message);
                let mut fail = PhaseFail::new(ErrorPhase::Tls, message);
                fail.hint = hint;
                fail
            })
        })
        .await?;
        let tls_ms = elapsed_ms(tls_start);

        // 스트림을 hyper로 넘기기 전에 세션 정보와 인증서 체인을 복사해 둔다.
        let (tls_info, cert_chain) = {
            let (_, session) = tls_stream.get_ref();
            extract_tls_session(session)
        };

        let use_h2 = tls_info.alpn.as_deref() == Some("h2");
        let (sender, guard) = http_handshake(tls_stream, use_h2, deadline).await?;
        (sender, guard, Some(tls_ms), Some(tls_info), cert_chain)
    } else {
        // http 스킴은 항상 http/1.1 (h2c 미지원).
        let (sender, guard) = http_handshake(tcp_stream, false, deadline).await?;
        (sender, guard, None, None, Vec::new())
    };

    Ok(ConnectedHop {
        sender,
        conn_guard,
        started: hop_start,
        ip,
        port,
        local_addr,
        resolved_ips,
        dns_ms,
        tcp_ms,
        tls_ms,
        tls_info,
        cert_chain,
    })
}

/// TLS 세션에서 협상 정보와 peer 인증서 체인(DER → CertInfo)을 복사한다.
/// connect_hop과 fetch_cert가 공용으로 사용한다.
fn extract_tls_session(session: &rustls::ClientConnection) -> (TlsInfo, Vec<CertInfo>) {
    let version = session
        .protocol_version()
        .map(|v| format!("{v:?}").replace('_', "."))
        .unwrap_or_else(|| "unknown".to_string());
    let cipher = session
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".to_string());
    let alpn = session
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).into_owned());
    let kx_group = session
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()));
    let der_chain: Vec<Vec<u8>> = session
        .peer_certificates()
        .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
        .unwrap_or_default();
    let cert_chain = crate::cert::parse_cert_chain(&der_chain);
    (
        TlsInfo {
            version,
            cipher,
            alpn,
            kx_group,
        },
        cert_chain,
    )
}

/// 리다이렉트 체인의 hop 1개: 연결 수립 → 요청 → 헤더 → 바디. 연결은 hop과 함께 폐기.
/// 두 번째 반환값은 body_contains 어설션용 바디 캡처
/// (cfg.expect.body_contains가 있을 때만 Some, 최대 BODY_CAPTURE_CAP).
async fn run_hop(
    cfg: &ProbeConfig,
    url: &Url,
    method: &str,
    body: Option<&str>,
    resolve: Option<IpAddr>,
    deadline: TokioInstant,
) -> Result<(HopResult, Option<Vec<u8>>), PhaseFail> {
    let mut conn = connect_hop(cfg, url, resolve, deadline).await?;
    let use_h2 = matches!(conn.sender, HttpSender::H2(_));

    // --- 요청 + TTFB + Download ----------------------------------------------
    let request = build_request(url, method, use_h2, &cfg.headers, body, cfg.keep_alive)?;
    let out = send_and_read(
        &mut conn.sender,
        request,
        cfg.expect.body_contains.is_some(),
        deadline,
    )
    .await?;
    let total_ms = elapsed_ms(conn.started);

    let hop = HopResult {
        url: url.to_string(),
        ip: conn.ip,
        port: conn.port,
        reused_conn: false,
        local_addr: conn.local_addr,
        resolved_ips: conn.resolved_ips,
        http_version: out.http_version,
        status: out.status,
        timings: PhaseTimings {
            dns_ms: conn.dns_ms,
            tcp_ms: conn.tcp_ms,
            tls_ms: conn.tls_ms,
            ttfb_ms: out.ttfb_ms,
            download_ms: out.download_ms,
            total_ms,
        },
        tls: conn.tls_info,
        cert_chain: conn.cert_chain,
        response_headers: out.response_headers,
        body_bytes: out.body_bytes,
        redirect_to: None, // 호출자(probe)가 Location 해석 후 채운다.
    };
    Ok((hop, out.body_capture))
}

/// 요청/응답 1회의 산출물 (send_and_read).
struct RequestOutcome {
    status: u16,
    http_version: String,
    response_headers: Vec<(String, String)>,
    body_bytes: u64,
    /// capture_body=true일 때 BODY_CAPTURE_CAP까지의 바디 앞부분 사본 (어설션용).
    body_capture: Option<Vec<u8>>,
    ttfb_ms: f64,
    download_ms: f64,
}

/// 수립된 연결로 요청 1회: 전송 → 헤더 수신(TTFB) → 바디 다운로드.
/// body_bytes는 캡처 여부/캡 한도와 무관하게 모든 데이터 프레임 바이트를 집계한다.
async fn send_and_read(
    sender: &mut HttpSender,
    request: Request<Full<Bytes>>,
    capture_body: bool,
    deadline: TokioInstant,
) -> Result<RequestOutcome, PhaseFail> {
    // --- 요청 + TTFB ---------------------------------------------------------
    let ttfb_start = Instant::now();
    let response = phase_await(deadline, ErrorPhase::Request, async {
        let result = match &mut *sender {
            HttpSender::H1(s) => s.send_request(request).await,
            HttpSender::H2(s) => s.send_request(request).await,
        };
        result.map_err(|e| {
            PhaseFail::new(
                ErrorPhase::Request,
                format!("request failed: {}", error_chain(&e)),
            )
        })
    })
    .await?;
    let ttfb_ms = elapsed_ms(ttfb_start);

    let status = response.status().as_u16();
    let http_version = http_version_str(response.version());
    // 수신 순서를 보존하며 헤더 수집. 비UTF-8 값은 lossy 변환.
    let response_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            let v = value
                .to_str()
                .map(str::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned());
            (name.as_str().to_owned(), v)
        })
        .collect();

    // --- Download -------------------------------------------------------------
    let download_start = Instant::now();
    let mut body_stream = response.into_body();
    let mut body_capture: Option<Vec<u8>> = capture_body.then(Vec::new);
    let body_bytes = phase_await(deadline, ErrorPhase::Download, async {
        let mut total: u64 = 0;
        while let Some(frame) = body_stream.frame().await {
            let frame = frame.map_err(|e| {
                PhaseFail::new(
                    ErrorPhase::Download,
                    format!("body read failed: {}", error_chain(&e)),
                )
            })?;
            if let Some(data) = frame.data_ref() {
                total += data.len() as u64;
                // 캡처는 캡 한도까지만 누적. total 집계는 항상 전체 기준.
                if let Some(buf) = body_capture.as_mut()
                    && buf.len() < BODY_CAPTURE_CAP
                {
                    let take = (BODY_CAPTURE_CAP - buf.len()).min(data.len());
                    buf.extend_from_slice(&data[..take]);
                }
            }
        }
        Ok(total)
    })
    .await?;
    let download_ms = elapsed_ms(download_start);

    Ok(RequestOutcome {
        status,
        http_version,
        response_headers,
        body_bytes,
        body_capture,
        ttfb_ms,
        download_ms,
    })
}

/// 스트림 위에서 hyper 클라이언트 핸드셰이크를 수행하고 conn 구동 태스크를 띄운다.
async fn http_handshake<T>(
    io: T,
    use_h2: bool,
    deadline: TokioInstant,
) -> Result<(HttpSender, AbortOnDrop), PhaseFail>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if use_h2 {
        let (sender, conn) = phase_await(deadline, ErrorPhase::Request, async {
            hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
                TokioExecutor::new(),
                TokioIo::new(io),
            )
            .await
            .map_err(|e| {
                PhaseFail::new(
                    ErrorPhase::Request,
                    format!("HTTP/2 handshake failed: {}", error_chain(&e)),
                )
            })
        })
        .await?;
        let handle = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((HttpSender::H2(sender), AbortOnDrop(handle)))
    } else {
        let (sender, conn) = phase_await(deadline, ErrorPhase::Request, async {
            hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(io))
                .await
                .map_err(|e| {
                    PhaseFail::new(
                        ErrorPhase::Request,
                        format!("HTTP/1.1 handshake failed: {}", error_chain(&e)),
                    )
                })
        })
        .await?;
        let handle = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((HttpSender::H1(sender), AbortOnDrop(handle)))
    }
}

/// 요청을 조립한다. http1은 origin-form URI + Host/Connection, h2는 절대 URI.
/// keep_alive면 http1에서도 Connection: close를 보내지 않는다 (연결 재사용 모드).
fn build_request(
    url: &Url,
    method: &str,
    use_h2: bool,
    user_headers: &[(String, String)],
    body: Option<&str>,
    keep_alive: bool,
) -> Result<Request<Full<Bytes>>, PhaseFail> {
    let setup = |msg: String| PhaseFail::new(ErrorPhase::Setup, msg);

    let method = Method::from_bytes(method.as_bytes())
        .map_err(|e| setup(format!("invalid method {method:?}: {e}")))?;

    let uri: Uri = if use_h2 {
        // h2: 절대 URI로 :scheme / :authority를 hyper가 채우게 한다.
        url[..url::Position::AfterQuery]
            .parse()
            .map_err(|e| setup(format!("invalid request URI: {e}")))?
    } else {
        // http1: origin-form (path + query).
        let mut pq = url.path().to_string();
        if let Some(q) = url.query() {
            pq.push('?');
            pq.push_str(q);
        }
        pq.parse()
            .map_err(|e| setup(format!("invalid request URI: {e}")))?
    };

    let mut builder = Request::builder().method(method).uri(uri);
    if use_h2 {
        builder = builder.version(Version::HTTP_2);
    }
    let body = match body {
        Some(b) => Full::new(Bytes::from(b.to_owned())),
        None => Full::default(),
    };
    let mut request = builder
        .body(body)
        .map_err(|e| setup(format!("failed to build request: {e}")))?;

    // 기본 헤더. Content-Length는 Full의 size hint로 hyper가 채우므로 직접 넣지 않는다.
    let headers = request.headers_mut();
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(concat!("httprove/", env!("CARGO_PKG_VERSION"))),
    );
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    if !use_h2 {
        // 비표준 포트면 host:port. url crate가 기본 포트는 None으로 정규화해 준다.
        let host_header = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        headers.insert(
            header::HOST,
            HeaderValue::from_str(&host_header)
                .map_err(|e| setup(format!("invalid host header: {e}")))?,
        );
        // keep-alive 모드는 연결을 재사용해야 하므로 close를 보내지 않는다.
        if !keep_alive {
            headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
    }

    // 사용자 헤더: 같은 이름(대소문자 무시)의 기본값을 덮어쓴다.
    // 사용자 헤더끼리 이름이 겹치면 두 번째부터는 append로 모두 전송.
    let mut overridden: Vec<HeaderName> = Vec::new();
    for (name, value) in user_headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| setup(format!("invalid header name {name:?}: {e}")))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|e| setup(format!("invalid value for header {name:?}: {e}")))?;
        if overridden.contains(&header_name) {
            headers.append(header_name, header_value);
        } else {
            headers.insert(header_name.clone(), header_value);
            overridden.push(header_name);
        }
    }

    Ok(request)
}

// ---------------------------------------------------------------------------
// TLS 설정
// ---------------------------------------------------------------------------

/// 네이티브 루트 저장소. 프로세스당 1회만 로드한다.
static NATIVE_ROOTS: OnceLock<Result<Arc<rustls::RootCertStore>, String>> = OnceLock::new();

fn native_root_store() -> Result<Arc<rustls::RootCertStore>, String> {
    NATIVE_ROOTS
        .get_or_init(|| {
            let result = rustls_native_certs::load_native_certs();
            let mut store = rustls::RootCertStore::empty();
            let mut added = 0usize;
            for cert in result.certs {
                if store.add(cert).is_ok() {
                    added += 1;
                }
            }
            if added == 0 {
                let detail = result
                    .errors
                    .first()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no certificates found".to_string());
                Err(format!("failed to load native root certificates: {detail}"))
            } else {
                Ok(Arc::new(store))
            }
        })
        .clone()
}

/// 설치된 기본 provider를 쓰고, 없으면 ring 기본값을 사용한다.
/// (ring provider는 크로스 컴파일 친화적이라 릴리스 4개 타깃 빌드를 단순화한다.)
fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// (insecure, http_version) 조합별 ClientConfig 캐시. 빌드에는 일회성 비용이 큰
/// 네이티브 루트 저장소 로드가 포함되므로 프로세스당 조합별 1회만 수행한다.
static TLS_CONFIG_CACHE: [OnceLock<Result<Arc<rustls::ClientConfig>, String>>; 4] =
    [const { OnceLock::new() }; 4];

fn tls_cache_index(insecure: bool, http_version: HttpVersionPref) -> usize {
    let insecure = usize::from(insecure);
    let http1 = usize::from(matches!(http_version, HttpVersionPref::Http1));
    insecure * 2 + http1
}

/// 캐시된 TLS ClientConfig를 반환한다 (첫 호출 시에만 빌드).
/// ProbeConfig 없이도 쓸 수 있도록 키 조합만 인자로 받는다 (fetch_cert 공용).
fn cached_tls_config(
    insecure: bool,
    http_version: HttpVersionPref,
) -> Result<Arc<rustls::ClientConfig>, String> {
    TLS_CONFIG_CACHE[tls_cache_index(insecure, http_version)]
        .get_or_init(|| build_tls_config(insecure, http_version))
        .clone()
}

/// 일회성 TLS 설정 비용을 측정 구간 밖에서 미리 지불한다 (https 대상일 때만).
/// 빌드 실패는 여기서 무시한다 — 실제 hop에서 같은 오류가 TLS 단계 실패로 보고된다.
fn warm_tls_config(cfg: &ProbeConfig) {
    if cfg.url.scheme() == "https" {
        let _ = cached_tls_config(cfg.insecure, cfg.http_version);
    }
}

fn build_tls_config(
    insecure: bool,
    http_version: HttpVersionPref,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let builder = rustls::ClientConfig::builder_with_provider(default_crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {e}"))?;

    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier::new()))
            .with_no_client_auth()
    } else {
        let roots = native_root_store()?;
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = match http_version {
        HttpVersionPref::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        HttpVersionPref::Http1 => vec![b"http/1.1".to_vec()],
    };
    Ok(Arc::new(config))
}

/// SNI용 ServerName. 도메인은 그대로, IP 리터럴은 IpAddress 변형으로.
fn sni_server_name(url: &Url) -> Result<ServerName<'static>, PhaseFail> {
    match url.host() {
        Some(url::Host::Domain(d)) => ServerName::try_from(d.to_owned())
            .map_err(|e| PhaseFail::new(ErrorPhase::Tls, format!("invalid SNI host name: {e}"))),
        Some(url::Host::Ipv4(ip)) => Ok(ServerName::from(IpAddr::V4(ip))),
        Some(url::Host::Ipv6(ip)) => Ok(ServerName::from(IpAddr::V6(ip))),
        None => Err(PhaseFail::new(
            ErrorPhase::Setup,
            "URL has no host".to_string(),
        )),
    }
}

/// --insecure 용: 모든 인증서를 수락하는 검증기. 체인 수집은 그대로 동작한다.
#[derive(Debug)]
struct InsecureVerifier {
    schemes: Vec<rustls::SignatureScheme>,
}

impl InsecureVerifier {
    fn new() -> Self {
        let schemes = default_crypto_provider()
            .signature_verification_algorithms
            .supported_schemes();
        Self { schemes }
    }
}

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

// ---------------------------------------------------------------------------
// 헬퍼
// ---------------------------------------------------------------------------

fn elapsed_ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn family_matches(ip: IpAddr, family: IpFamily) -> bool {
    match family {
        IpFamily::Auto => true,
        IpFamily::V4 => ip.is_ipv4(),
        IpFamily::V6 => ip.is_ipv6(),
    }
}

/// 에러 체인 전체를 사람이 읽을 수 있는 한 줄로 합친다 (중복 표시는 생략).
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = s.source();
    }
    message
}

fn http_version_str(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    }
    .to_string()
}

/// 응답 헤더 목록에서 이름(대소문자 무시)으로 첫 값을 찾는다.
fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// 3xx 응답의 Location을 절대 URL로 해석한다 (keep-alive 모드 — 따라가지는 않음).
/// 3xx가 아니거나 Location이 없거나 해석 불가능하면 None.
fn resolve_redirect_to(base: &Url, status: u16, headers: &[(String, String)]) -> Option<String> {
    if !(300..400).contains(&status) {
        return None;
    }
    let loc = find_header(headers, "location")?;
    base.join(&loc).ok().map(|u| u.to_string())
}

// ---------------------------------------------------------------------------
// keep-alive 모드 / 인증서 전용 조회 (probe 에이전트가 구현)
// ---------------------------------------------------------------------------

/// keep-alive 프로브: 연결을 유지한 채 같은 대상으로 반복 요청한다.
///
/// 동작 규칙:
/// - 첫 probe() 호출 또는 직전 요청이 실패한 다음 호출: 새로 연결하며 전체 단계
///   (dns/tcp/tls)를 측정한다 (reused_conn=false). 연결 핸들(HttpSender + conn 태스크)과
///   연결 시점의 TLS/인증서 정보를 보관한다.
/// - 이후 호출: 기존 연결로 요청만 보낸다. dns/tls=None, tcp_ms=0.0,
///   reused_conn=true. TLS/인증서 정보는 연결 시점 값을 재사용해 채운다.
/// - 보관 중인 연결이 이미 닫혀 있으면(sender.is_closed() — 서버 idle timeout,
///   keepalive_requests 회전, h2 GOAWAY): 에러를 내지 않고 그 호출에서 바로
///   전체 단계 재연결 프로브를 수행한다 (reused_conn=false).
/// - 요청/다운로드 실패 시: 해당 ProbeResult는 에러로 보고하고 연결을 버린다.
///   다음 호출에서 자동으로 재연결한다.
/// - http1은 Connection: close를 보내지 않는다 (cfg.keep_alive로 build_request 분기).
///   h2는 SendRequest 재사용.
/// - 리다이렉트는 따라가지 않는다 (cli에서 -L과 동시 사용을 금지함). 3xx도 그대로 결과.
/// - cfg.timeout은 각 probe() 호출마다 새 데드라인.
/// - expect 어설션은 일반 probe와 동일하게 평가.
pub struct KeepAliveProber {
    cfg: ProbeConfig,
    /// 살아있는 연결 상태. None이면 다음 probe()에서 새로 연결한다.
    established: Option<Established>,
}

/// 연결 시점에 수집한 상태. 재사용 hop의 HopResult 필드를 채우는 데 재사용한다.
struct Established {
    sender: HttpSender,
    /// conn 구동 태스크 가드. Established가 버려지면 태스크도 함께 중단된다
    /// (h1/h2 모두 — 송신기 drop과 별개로 abort까지 보장해 누수를 막는다).
    _conn_guard: AbortOnDrop,
    ip: IpAddr,
    port: u16,
    local_addr: Option<SocketAddr>,
    resolved_ips: Vec<IpAddr>,
    /// 첫 응답에서 관측한 HTTP 버전 (재사용 hop에 그대로 기록).
    http_version: String,
    tls: Option<TlsInfo>,
    cert_chain: Vec<CertInfo>,
}

impl KeepAliveProber {
    pub fn new(cfg: ProbeConfig) -> Self {
        Self {
            cfg,
            established: None,
        }
    }

    /// 연결을 재사용하며 프로브 1회 실행. 실패는 ProbeResult.error로 보고.
    pub async fn probe(&mut self, seq: u64) -> ProbeResult {
        // 일반 probe()와 동일하게 일회성 TLS 설정 비용을 타이머 밖에서 지불한다.
        warm_tls_config(&self.cfg);
        let timestamp = chrono::Utc::now();
        let start = Instant::now();
        // 매 호출마다 cfg.timeout 기준의 새 데드라인.
        let deadline = TokioInstant::now() + self.cfg.timeout;

        // 보관 중인 연결이 이미 닫혔으면(서버 idle timeout, keepalive_requests 회전,
        // h2 GOAWAY 등) 죽은 연결로 요청을 시도해 가짜 에러를 만들지 말고 버린 뒤
        // 곧바로 전체 단계 재연결 프로브로 진행한다 (reused_conn=false).
        // 검사 직후 FIN이 도착하는 경합은 불가피 — 그 경우만 Request 에러로 남는다.
        if self
            .established
            .as_ref()
            .is_some_and(|est| est.sender.is_closed())
        {
            // Established drop으로 conn 구동 태스크도 함께 중단된다.
            self.established = None;
        }

        let outcome = if self.established.is_some() {
            self.probe_reused(deadline).await
        } else {
            self.probe_connect(deadline).await
        };
        let (hops, error, final_capture) = match outcome {
            Ok((hop, capture)) => (vec![hop], None, capture),
            Err(fail) => (Vec::new(), Some(fail.into_probe_error()), None),
        };

        let mut result = ProbeResult {
            target: self.cfg.url.to_string(),
            seq,
            timestamp,
            hops,
            error,
            expect_failures: vec![],
            total_ms: elapsed_ms(start),
        };
        evaluate_expectations(&mut result, &self.cfg.expect, final_capture.as_deref());
        result
    }

    /// 기존 연결로 요청 1회. 어떤 실패든 연결을 폐기한다 (다음 호출에서 자동 재연결).
    async fn probe_reused(
        &mut self,
        deadline: TokioInstant,
    ) -> Result<(HopResult, Option<Vec<u8>>), PhaseFail> {
        // 호출 분기에서 Some임을 확인했지만 방어적으로 한 번 더 확인한다.
        let Some(est) = self.established.as_mut() else {
            return Err(PhaseFail::new(
                ErrorPhase::Setup,
                "no established connection".to_string(),
            ));
        };
        let result = Self::request_on(&self.cfg, est, deadline).await;
        if result.is_err() {
            // 죽은 연결을 들고 있지 않는다. Established drop으로 conn 태스크도 중단된다.
            self.established = None;
        }
        result
    }

    /// 수립된 연결 위에서 요청 1회를 보내고 재사용 hop의 HopResult를 만든다.
    async fn request_on(
        cfg: &ProbeConfig,
        est: &mut Established,
        deadline: TokioInstant,
    ) -> Result<(HopResult, Option<Vec<u8>>), PhaseFail> {
        let req_start = Instant::now();

        // 직전 응답 처리 직후 디스패처가 아직 준비 전일 수 있으므로 ready를 기다린다.
        // 서버가 사이에 연결을 닫았다면 여기서 실패한다.
        phase_await(deadline, ErrorPhase::Request, async {
            let ready = match &mut est.sender {
                HttpSender::H1(s) => s.ready().await,
                HttpSender::H2(s) => s.ready().await,
            };
            ready.map_err(|e| {
                PhaseFail::new(
                    ErrorPhase::Request,
                    format!("connection not ready: {}", error_chain(&e)),
                )
            })
        })
        .await?;

        let use_h2 = matches!(est.sender, HttpSender::H2(_));
        let request = build_request(
            &cfg.url,
            &cfg.method,
            use_h2,
            &cfg.headers,
            cfg.body.as_deref(),
            cfg.keep_alive,
        )?;
        let out = send_and_read(
            &mut est.sender,
            request,
            cfg.expect.body_contains.is_some(),
            deadline,
        )
        .await?;
        // 재사용 hop의 total은 이 요청의 실측 wall clock (연결 단계 없음).
        let total_ms = elapsed_ms(req_start);

        let mut hop = HopResult {
            url: cfg.url.to_string(),
            ip: est.ip,
            port: est.port,
            reused_conn: true,
            local_addr: est.local_addr,
            resolved_ips: est.resolved_ips.clone(),
            http_version: est.http_version.clone(),
            status: out.status,
            timings: PhaseTimings {
                dns_ms: None,
                tcp_ms: 0.0,
                tls_ms: None,
                ttfb_ms: out.ttfb_ms,
                download_ms: out.download_ms,
                total_ms,
            },
            tls: est.tls.clone(),
            cert_chain: est.cert_chain.clone(),
            response_headers: out.response_headers,
            body_bytes: out.body_bytes,
            redirect_to: None,
        };
        // 3xx면 Location만 절대 URL로 기록하고 따라가지 않는다 (-L과 동시 사용 불가).
        hop.redirect_to = resolve_redirect_to(&cfg.url, out.status, &hop.response_headers);
        Ok((hop, out.body_capture))
    }

    /// 새 연결 수립 + 첫 요청 (전체 단계 측정). 성공 시 연결을 보관한다.
    async fn probe_connect(
        &mut self,
        deadline: TokioInstant,
    ) -> Result<(HopResult, Option<Vec<u8>>), PhaseFail> {
        let cfg = &self.cfg;
        // 연결 실패(`?`) → disconnected 상태 유지, 다음 호출에서 다시 시도.
        let mut conn = connect_hop(cfg, &cfg.url, cfg.resolve, deadline).await?;
        let use_h2 = matches!(conn.sender, HttpSender::H2(_));

        let request = build_request(
            &cfg.url,
            &cfg.method,
            use_h2,
            &cfg.headers,
            cfg.body.as_deref(),
            cfg.keep_alive,
        )?;
        // 첫 요청 실패 시에는 연결을 보관하지 않는다 (`?` 조기 반환 → conn drop,
        // AbortOnDrop이 conn 태스크를 중단시킨다).
        let out = send_and_read(
            &mut conn.sender,
            request,
            cfg.expect.body_contains.is_some(),
            deadline,
        )
        .await?;
        let total_ms = elapsed_ms(conn.started);

        let mut hop = HopResult {
            url: cfg.url.to_string(),
            ip: conn.ip,
            port: conn.port,
            reused_conn: false,
            local_addr: conn.local_addr,
            resolved_ips: conn.resolved_ips.clone(),
            http_version: out.http_version.clone(),
            status: out.status,
            timings: PhaseTimings {
                dns_ms: conn.dns_ms,
                tcp_ms: conn.tcp_ms,
                tls_ms: conn.tls_ms,
                ttfb_ms: out.ttfb_ms,
                download_ms: out.download_ms,
                total_ms,
            },
            tls: conn.tls_info.clone(),
            cert_chain: conn.cert_chain.clone(),
            response_headers: out.response_headers,
            body_bytes: out.body_bytes,
            redirect_to: None,
        };
        hop.redirect_to = resolve_redirect_to(&cfg.url, out.status, &hop.response_headers);

        // 다음 호출에서 재사용할 연결 상태 보관 (연결 시점 메타데이터 포함).
        self.established = Some(Established {
            sender: conn.sender,
            _conn_guard: conn.conn_guard,
            ip: conn.ip,
            port: conn.port,
            local_addr: conn.local_addr,
            resolved_ips: conn.resolved_ips,
            http_version: out.http_version,
            tls: conn.tls_info,
            cert_chain: conn.cert_chain,
        });
        Ok((hop, out.body_capture))
    }
}

/// TLS 핸드셰이크까지만 수행해 인증서 체인을 가져온다 (HTTP 요청 없음).
/// `--cert-check` 모드용. host는 SNI로도 사용된다.
///
/// DNS(시스템 리졸버) → TCP → TLS 핸드셰이크 순서로 진행하고, 세션 정보를 복사한
/// 뒤 스트림은 그대로 버린다. timeout이 세 단계 전체를 덮는다.
pub async fn fetch_cert(
    host: &str,
    port: u16,
    timeout: std::time::Duration,
    insecure: bool,
) -> Result<(crate::types::TlsInfo, Vec<crate::types::CertInfo>), String> {
    // probe와 같은 TLS 설정 캐시를 재사용한다 (일회성 빌드 비용은 측정 대상 아님).
    let tls_config = cached_tls_config(insecure, HttpVersionPref::Auto)?;

    // SNI: 도메인 또는 IP 리터럴. DNS-safe하지 않은 호스트명은 여기서 걸러진다.
    let sni: ServerName<'static> = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::from(ip),
        Err(_) => ServerName::try_from(host.to_owned())
            .map_err(|e| format!("invalid server name {host:?}: {e}"))?,
    };

    let deadline = TokioInstant::now() + timeout;
    let attempt = async {
        // --- DNS — 첫 주소 사용 ------------------------------------------------
        let addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("DNS lookup for {host:?} failed: {}", error_chain(&e)))?
            .next()
            .ok_or_else(|| format!("no addresses found for {host}"))?;

        // --- TCP ----------------------------------------------------------------
        let tcp_stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect to {addr} failed: {}", error_chain(&e)))?;
        let _ = tcp_stream.set_nodelay(true);

        // --- TLS 핸드셰이크까지만 — 세션 정보 복사 후 스트림은 버린다 ----------------
        let connector = TlsConnector::from(tls_config);
        let tls_stream = connector
            .connect(sni, tcp_stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", error_chain(&e)))?;
        let (_, session) = tls_stream.get_ref();
        Ok(extract_tls_session(session))
    };
    match tokio::time::timeout_at(deadline, attempt).await {
        Ok(result) => result,
        Err(_) => Err(format!("timed out after {:.1}s", timeout.as_secs_f64())),
    }
}
