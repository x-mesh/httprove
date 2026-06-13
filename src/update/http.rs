//! update 전용 최소 HTTPS 클라이언트 (hyper + tokio-rustls 재사용).
//!
//! 자가 업데이트만을 위한 작은 GET/HEAD 클라이언트다. 새 HTTP 의존성을 추가하지
//! 않으려고 기존 rustls/hyper 스택 위에 직접 구현한다.
//!
//! - HTTPS만 지원 (GitHub 릴리스 호스트 대상).
//! - 리다이렉트(301/302/303/307/308)를 호스트를 바꿔가며 최대 MAX_REDIRECTS회 따라간다
//!   (릴리스 다운로드는 github.com → objects.githubusercontent.com 으로 넘어감).
//! - HEAD 요청에서는 리다이렉트를 따라가지 않고 첫 Location을 그대로 돌려준다
//!   (latest 태그 해석용).
//! - 응답 바디는 max_bytes까지만 읽는다 (메모리 보호).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_REDIRECTS: u32 = 10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const USER_AGENT: &str = concat!("httprove/", env!("CARGO_PKG_VERSION"), " (self-update)");

/// HTTP 응답 (필요한 최소 정보만).
pub struct Response {
    pub status: u16,
    /// 리다이렉트 응답의 Location 헤더 (있으면).
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// GET 요청. 리다이렉트를 끝까지 따라가고 바디를 max_bytes까지 읽는다.
pub async fn get(url: &str, max_bytes: usize) -> Result<Response, String> {
    request("GET", url, true, max_bytes).await
}

/// HEAD 요청. 리다이렉트를 따라가지 않고 첫 응답(주로 3xx + Location)을 반환한다.
pub async fn head_no_follow(url: &str) -> Result<Response, String> {
    request("HEAD", url, false, 0).await
}

async fn request(
    method: &str,
    url: &str,
    follow: bool,
    max_bytes: usize,
) -> Result<Response, String> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let resp = request_once(method, &current, max_bytes).await?;
        let is_redirect = (300..400).contains(&resp.status) && resp.location.is_some();
        if follow && is_redirect {
            let loc = resp.location.as_deref().unwrap();
            current = resolve_redirect(&current, loc)?;
            continue;
        }
        return Ok(resp);
    }
    Err(format!("too many redirects fetching {url}"))
}

/// 리다이렉트 Location을 절대 URL로 해석한다 (상대 경로 대응).
fn resolve_redirect(base: &str, location: &str) -> Result<String, String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    // 상대 경로 — base의 스킴+호스트에 결합.
    let uri: Uri = base.parse().map_err(|e| format!("parse base url: {e}"))?;
    let scheme = uri.scheme_str().unwrap_or("https");
    let authority = uri
        .authority()
        .map(|a| a.as_str())
        .ok_or_else(|| "base url missing host".to_string())?;
    if let Some(stripped) = location.strip_prefix('/') {
        Ok(format!("{scheme}://{authority}/{stripped}"))
    } else {
        Ok(format!("{scheme}://{authority}/{location}"))
    }
}

async fn request_once(method: &str, url: &str, max_bytes: usize) -> Result<Response, String> {
    let uri: Uri = url.parse().map_err(|e| format!("invalid url {url}: {e}"))?;
    if uri.scheme_str() != Some("https") {
        return Err(format!("only https is supported, got: {url}"));
    }
    let host = uri
        .host()
        .ok_or_else(|| format!("url has no host: {url}"))?
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    // --- TCP + TLS ---
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| format!("connect to {host}:{port} timed out"))?
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;
    tcp.set_nodelay(true).ok();

    let connector = TlsConnector::from(tls_config()?);
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| format!("invalid server name {host}: {e}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls handshake with {host}: {e}"))?;

    // --- HTTP/1.1 ---
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    // 연결 구동 태스크 — 요청 완료 후 sender drop으로 종료된다.
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let authority = match port {
        443 => host.clone(),
        p => format!("{host}:{p}"),
    };
    let req = Request::builder()
        .method(method)
        .uri(&path)
        .header(http::header::HOST, &authority)
        .header(http::header::USER_AGENT, USER_AGENT)
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::CONNECTION, "close")
        .body(Full::<Bytes>::default())
        .map_err(|e| format!("build request: {e}"))?;

    let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| format!("send request to {host}: {e}"))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        // HEAD거나 max_bytes==0이면 바디를 읽지 않는다.
        let mut body = Vec::new();
        if max_bytes > 0 {
            let mut stream = resp.into_body();
            while let Some(frame) = stream.frame().await {
                let frame = frame.map_err(|e| format!("read body from {host}: {e}"))?;
                if let Some(data) = frame.data_ref() {
                    if body.len() + data.len() > max_bytes {
                        return Err(format!(
                            "response from {host} exceeds {max_bytes} byte limit"
                        ));
                    }
                    body.extend_from_slice(data);
                }
            }
        }
        Ok::<Response, String>(Response {
            status,
            location,
            body,
        })
    })
    .await
    .map_err(|_| format!("request to {host} timed out"))?;

    conn_task.abort();
    result
}

/// 네이티브 루트 인증서로 만든 rustls ClientConfig (프로세스당 1회 빌드).
fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            if loaded.certs.is_empty() {
                return Err("no native root certificates found".to_string());
            }
            for cert in loaded.certs {
                // 개별 인증서 파싱 실패는 무시하고 나머지로 진행.
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}
