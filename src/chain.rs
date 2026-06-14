//! 인증서 체인 완결성 + AIA 복구 + TLS 핸드셰이크 오류 디코더, 체인 전체 만료 분석.
//!
//! 담당 기능:
//! - ㉑ 체인 완결성/AIA/핸드셰이크 디코더
//! - ㉒ 체인 전체(whole-chain)의 최약 링크 만료
//!
//! ## analyze(chain) -> ChainAnalysis   (㉒ + ㉑ 휴리스틱, 순수 함수)
//! - 빈 체인이어도 **패닉 금지**: incomplete=false, weakest_days=i64::MAX(또는 0),
//!   weakest_subject="" 등 합리적 기본값으로 ChainAnalysis::default() 기반 반환.
//! - weakest_days: 체인 내 모든 CertInfo.days_remaining의 **최솟값** (가장 먼저 죽는 인증서).
//! - weakest_subject: 그 최솟값 인증서의 subject에서 추출한 CN (cn_of 사용).
//! - incomplete(불완전 추정 휴리스틱): 체인 cert가 **딱 1개**이고
//!   그 leaf가 `is_ca == false`이며 `issuer != subject`(자가서명 아님)이면
//!   중간 인증서 누락으로 본다 => incomplete=true.
//! - issues: 사람이 읽을 한 줄들. 예:
//!     - incomplete면 "intermediate certificate(s) missing — server sent leaf only".
//!     - 체인 내 어떤 cert의 issuer가 다음 cert의 subject와 불일치하면
//!       "chain order/issuer mismatch near <CN>".
//!     - 루트/상위가 leaf보다 먼저 만료되면 "issuer '<CN>' expires before leaf (<Nd>)".
//!     - 이미 만료된 cert가 있으면 "<CN> already expired (<Nd> ago)".
//!
//!   (가능한 항목만, 비어 있을 수 있음.)
//!
//! ## check_aia(chain, leaf_der, timeout) -> ChainAnalysis   (㉑, best-effort 네트워크)
//! - 먼저 analyze(chain) 결과를 기반으로 시작한다.
//! - incomplete가 아니면 aia_repairable는 그대로 None 두고 반환(조회 불필요).
//! - incomplete이고 leaf_der가 Some이면:
//!   1. x509-parser로 leaf DER을 파싱해 Authority Information Access 확장에서
//!      caIssuers(accessMethod = id-ad-caIssuers) URL을 추출한다.
//!   2. 그 URL(http/https)을 update/http.rs의 GET 패턴과 동일한 최소 클라이언트로 가져온다
//!      (timeout 적용). DER(application/pkix-cert) 또는 PEM 응답을 받으면
//!      issuer 인증서를 얻은 것이므로 aia_repairable=Some(true).
//!   3. URL이 없거나 fetch/parse 실패면 aia_repairable=Some(false).
//!
//!   네트워크 오류는 로그/무시 — **best-effort**, 패닉/하드 에러 금지.
//! - http GET이 https라면 update/http.rs의 get을 그대로 쓰는 방안과, http면 별도 최소 구현이
//!   필요할 수 있다. caIssuers는 보통 http다 — 간단한 HTTP/1.1 GET을 직접 구현하거나
//!   update::http 패턴을 http로 확장해 재사용한다(새 의존성 없이 hyper http1 사용).
//!
//! ## decode_tls_error(message) -> Option<String>   (㉑ 분류기, 순수 함수)
//! rustls/TLS 오류 문자열을 사람이 이해할 원인 + 한 줄 해법으로 분류한다.
//! probe.rs의 핸드셰이크 실패 지점에서 hint로 쓰인다.
//! 인식 가능한 패턴(부분 문자열/키워드 매칭, 대소문자 무시) 예:
//!   - "expired"/"not valid after"  → leaf vs intermediate 만료 구분 시도,
//!     "Server certificate (or an intermediate) has expired — renew/reissue it."
//!   - "UnknownIssuer"/"unable to get local issuer"/"incomplete"
//!     → "Server didn't send the full chain — install the intermediate certificate."
//!   - "NotValidForName"/"hostname"/"SAN"/"name mismatch"
//!     → "Certificate is not valid for this hostname — check SAN/CN vs the URL host."
//!   - "UnknownCA"/"self signed"/"self-signed"/"untrusted"
//!     → "Root not trusted — add the CA to the trust store or use a public CA."
//!   - "no server name"/"SNI"/"missing_extension"
//!     → "Server requires SNI — connect by hostname, not by raw IP."
//!   - "protocol version"/"version"/"TLS1"/"legacy"
//!     → "TLS version too old/refused — server enforces a newer floor (e.g. TLS 1.2+)."
//!   - "revoked"/"revocation"
//!     → "Certificate revoked — reissue; client checked CRL/OCSP."
//!
//! 인식 불가하면 None.
//!
//! ## cn_of(subject) 헬퍼
//! RFC2253 형태 subject("CN=example.com,O=Foo,C=US")에서 CN 값을 추출한다.
//! CN이 없으면 subject 원문을 그대로 돌려주는 식의 폴백 권장. 순수 함수.
//!
//! ## 구현 메모
//! - analyze는 절대 패닉하지 않는다(빈 체인/CN 없음 모두 안전).
//! - 모든 fallible 경로는 Result/Option. 네트워크는 best-effort.
//! - #[cfg(test)]로 cn_of, analyze(불완전 체인/만료 체인), decode_tls_error 매칭을 검증 권장.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::types::{CertInfo, ChainAnalysis};

/// AIA caIssuers 응답 본문 상한 (인증서 1~2장이면 충분; 메모리 보호).
const AIA_MAX_BYTES: usize = 256 * 1024;

/// 체인 완결성 휴리스틱 + 최약 링크 만료 분석 (순수, 패닉 없음).
pub fn analyze(chain: &[CertInfo]) -> ChainAnalysis {
    // 빈 체인: 합리적 기본값(패닉 금지). weakest_days=0으로 두어 "정보 없음"을 표현.
    if chain.is_empty() {
        return ChainAnalysis::default();
    }

    // --- 최약 링크: days_remaining 최솟값과 그 cert의 CN ---
    // (leaf 먼저 순서이므로, 동률이면 더 앞선 cert를 유지한다.)
    let mut weakest_idx = 0usize;
    for (i, cert) in chain.iter().enumerate() {
        if cert.days_remaining < chain[weakest_idx].days_remaining {
            weakest_idx = i;
        }
    }
    let weakest_days = chain[weakest_idx].days_remaining;
    let weakest_subject = cn_of(&chain[weakest_idx].subject);

    // --- 완결성 휴리스틱: leaf 단독 + 비-CA + 자가서명 아님 => 중간 인증서 누락 추정 ---
    let leaf = &chain[0];
    let incomplete = chain.len() == 1 && !leaf.is_ca && leaf.issuer != leaf.subject;

    // --- 사람이 읽을 issues ---
    let mut issues = Vec::new();

    if incomplete {
        issues.push("intermediate certificate(s) missing — server sent leaf only".to_string());
    }

    // 체인 순서/issuer 불일치: cert[i].issuer != cert[i+1].subject 이면 끊긴 것.
    // (placeholder cert는 issuer가 비어 있을 수 있으므로 빈 값은 건너뛴다.)
    for i in 0..chain.len().saturating_sub(1) {
        let cur = &chain[i];
        let next = &chain[i + 1];
        if cur.issuer.is_empty() || next.subject.is_empty() {
            continue;
        }
        if cur.issuer != next.subject {
            issues.push(format!(
                "chain order/issuer mismatch near {}",
                cn_of(&cur.subject)
            ));
        }
    }

    // 상위(non-leaf) 인증서가 leaf보다 먼저 만료되면 경고.
    let leaf_days = leaf.days_remaining;
    for cert in chain.iter().skip(1) {
        if cert.days_remaining < leaf_days {
            issues.push(format!(
                "issuer '{}' expires before leaf ({}d)",
                cn_of(&cert.subject),
                cert.days_remaining
            ));
        }
    }

    // 이미 만료된 cert(들).
    for cert in chain.iter() {
        if cert.days_remaining < 0 {
            issues.push(format!(
                "{} already expired ({}d ago)",
                cn_of(&cert.subject),
                cert.days_remaining.abs()
            ));
        }
    }

    ChainAnalysis {
        incomplete,
        aia_repairable: None,
        weakest_days,
        weakest_subject,
        issues,
    }
}

/// 불완전 체인이면 leaf의 AIA caIssuers로 issuer를 받아 복구 가능성을 판정한다 (best-effort).
///
/// caIssuers URL은 leaf 인증서(chain[0])의 `aia_ca_issuers`에서 가져온다 — DER을 따로
/// 보관하지 않아도 cert 파싱 시점(cert.rs)에 추출해 둔 값을 재사용한다.
pub async fn check_aia(chain: &[CertInfo], timeout: Duration) -> ChainAnalysis {
    let mut analysis = analyze(chain);

    // 완결 체인이면 AIA 조회 불필요 — aia_repairable는 None 유지.
    if !analysis.incomplete {
        return analysis;
    }

    // leaf의 caIssuers URL이 있으면 fetch → issuer 파싱 가능하면 repairable.
    // URL이 없으면(확장 부재/누락) aia_repairable=Some(false).
    let repairable = match chain.first().and_then(|c| c.aia_ca_issuers.as_deref()) {
        Some(url) => fetch_issuer_cert(url, timeout).await,
        None => false,
    };
    analysis.aia_repairable = Some(repairable);
    analysis
}

/// caIssuers URL을 GET 해 issuer 인증서를 파싱할 수 있는지 본다 (best-effort).
/// DER(application/pkix-cert) 또는 PEM/PKCS#7 응답을 받아 인증서 1장 이상 파싱되면 true.
async fn fetch_issuer_cert(url: &str, timeout: Duration) -> bool {
    match http_get(url, timeout, AIA_MAX_BYTES).await {
        Ok(body) => body_contains_cert(&body),
        // 네트워크/파싱 오류는 best-effort: 복구 불가로 본다(패닉/하드 에러 금지).
        Err(_) => false,
    }
}

/// 응답 본문이 인증서를 담고 있는지 판별한다.
/// 1) DER로 바로 파싱 시도, 2) PEM 블록(BEGIN CERTIFICATE) 디코드 후 DER 파싱,
/// 3) PKCS#7(SEQUENCE) 컨테이너면 내부에서 인증서 DER 패턴을 탐색.
///
/// 외부 base64/PEM 의존성을 더하지 않으려고 최소 디코더를 직접 둔다.
fn body_contains_cert(body: &[u8]) -> bool {
    // 1) 순수 DER 응답 (가장 흔한 application/pkix-cert).
    if X509Certificate::from_der(body).is_ok() {
        return true;
    }

    // 2) PEM 텍스트 응답: BEGIN/END CERTIFICATE 사이를 base64 디코드.
    if let Ok(text) = std::str::from_utf8(body)
        && let Some(der) = first_pem_certificate(text)
        && X509Certificate::from_der(&der).is_ok()
    {
        return true;
    }

    // 3) PKCS#7(.p7c) 등 컨테이너: 내부에 첫 X.509 SEQUENCE가 있으면 인증서로 간주.
    //    SEQUENCE 태그(0x30)에서 시작하는 슬라이스를 훑어 파싱 가능한 첫 cert를 찾는다.
    contains_der_certificate(body)
}

/// PEM 텍스트에서 첫 CERTIFICATE 블록을 찾아 DER 바이트로 디코드한다.
fn first_pem_certificate(text: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = text.find(BEGIN)? + BEGIN.len();
    let end = text[start..].find(END)? + start;
    let b64: String = text[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64_decode(&b64)
}

/// 본문 안에서 파싱 가능한 첫 DER 인증서(SEQUENCE)를 탐색한다 (PKCS#7 컨테이너 대응).
/// 비용 보호를 위해 앞쪽 일부 오프셋의 SEQUENCE 시작점만 시도한다.
fn contains_der_certificate(body: &[u8]) -> bool {
    const MAX_SCAN_OFFSETS: usize = 4096;
    let limit = body.len().min(MAX_SCAN_OFFSETS);
    for i in 0..limit {
        // X.509 Certificate는 항상 SEQUENCE(0x30)로 시작한다.
        if body[i] != 0x30 {
            continue;
        }
        if X509Certificate::from_der(&body[i..]).is_ok() {
            return true;
        }
    }
    false
}

/// 표준 base64 디코더 (외부 crate 의존 없이). 패딩/공백 허용, 잘못된 입력이면 None.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let n = chunk.len();
        if n < 2 {
            return None;
        }
        for (i, &c) in chunk.iter().enumerate() {
            buf[i] = val(c)?;
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if n >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if n == 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(out)
}

// ===========================================================================
// 최소 HTTP/HTTPS GET 클라이언트 (update/http.rs 패턴 기반, http+https 모두 지원).
// caIssuers URL은 보통 http이므로 평문 경로도 필요하다. 새 의존성 없이 hyper http1 사용.
// ===========================================================================

/// http/https URL을 GET 해 본문을 max_bytes까지 읽는다 (timeout 적용, 리다이렉트 미추적).
/// AIA caIssuers는 보통 단일 응답이라 리다이렉트는 따라가지 않는다.
async fn http_get(url: &str, timeout: Duration, max_bytes: usize) -> Result<Vec<u8>, String> {
    let fut = http_get_inner(url, max_bytes);
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| format!("request to {url} timed out"))?
}

async fn http_get_inner(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let uri: Uri = url.parse().map_err(|e| format!("invalid url {url}: {e}"))?;
    let scheme = uri.scheme_str().unwrap_or("http");
    let is_https = scheme == "https";
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme in {url}"));
    }
    let host = uri
        .host()
        .ok_or_else(|| format!("url has no host: {url}"))?
        .to_string();
    let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let authority = match (is_https, port) {
        (true, 443) | (false, 80) => host.clone(),
        (_, p) => format!("{host}:{p}"),
    };

    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;
    tcp.set_nodelay(true).ok();

    // 스킴별로 스트림 타입이 달라 핸드셰이크/요청을 각 분기에서 끝낸다.
    if is_https {
        let connector = TlsConnector::from(tls_config()?);
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| format!("invalid server name {host}: {e}"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("tls handshake with {host}: {e}"))?;
        send_get(TokioIo::new(tls), &path, &authority, &host, max_bytes).await
    } else {
        send_get(TokioIo::new(tcp), &path, &authority, &host, max_bytes).await
    }
}

/// 핸드셰이크된 IO 위에서 HTTP/1.1 GET을 보내고 본문을 max_bytes까지 읽는다.
async fn send_get<I>(
    io: I,
    path: &str,
    authority: &str,
    host: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    // 연결 구동 태스크 — 요청 완료 후 sender drop으로 종료된다.
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let user_agent = concat!("httprove/", env!("CARGO_PKG_VERSION"), " (check-chain)");
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(http::header::HOST, authority)
        .header(http::header::USER_AGENT, user_agent)
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::CONNECTION, "close")
        .body(Full::<Bytes>::default())
        .map_err(|e| format!("build request: {e}"))?;

    let result = async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| format!("send request to {host}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{host} returned HTTP {}", resp.status().as_u16()));
        }
        let mut body = Vec::new();
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
        Ok::<Vec<u8>, String>(body)
    }
    .await;

    conn_task.abort();
    result
}

/// 네이티브 루트 인증서로 만든 rustls ClientConfig (프로세스당 1회 빌드).
/// caIssuers가 https인 드문 경우에만 쓰인다.
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

/// RFC2253 형태 subject에서 CN 값을 추출한다. CN이 없으면 원문 그대로 폴백.
fn cn_of(subject: &str) -> String {
    // subject 예: "CN=example.com, O=Foo, C=US" 또는 "CN=example.com,O=Foo".
    // RDN은 콤마로 구분되지만 값 안의 이스케이프된 콤마(\,)는 구분자가 아니다.
    let mut start = 0usize;
    let bytes = subject.as_bytes();
    let mut i = 0usize;
    while i <= bytes.len() {
        let at_sep = i == bytes.len() || (bytes[i] == b',' && (i == 0 || bytes[i - 1] != b'\\'));
        if at_sep {
            let rdn = subject[start..i].trim();
            // "CN=value" 외에 "CN = value"처럼 등호 주위에 공백이 있는 인코딩도 허용한다.
            if let Some(cn) = strip_cn_prefix(rdn) {
                let cn = cn.trim();
                if !cn.is_empty() {
                    return cn.to_string();
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    // CN 미발견: subject 원문 폴백.
    subject.to_string()
}

/// RDN에서 "CN"/"cn" 속성 접두를 (등호 주위 공백 허용) 떼어내 값 부분을 돌려준다.
/// CN RDN이 아니면 None.
fn strip_cn_prefix(rdn: &str) -> Option<&str> {
    let rest = rdn
        .strip_prefix("CN")
        .or_else(|| rdn.strip_prefix("cn"))?
        .trim_start();
    rest.strip_prefix('=').map(str::trim_start)
}

/// rustls/TLS 오류 문자열을 사람이 이해할 원인+해법으로 분류 (인식 불가면 None).
pub fn decode_tls_error(message: &str) -> Option<String> {
    let m = message.to_ascii_lowercase();
    let has = |needle: &str| m.contains(needle);

    // 순서 주의: 더 구체적인 원인을 먼저 매칭한다.
    // 만료: rustls Display "invalid peer certificate: Expired", CertExpired, "not valid after".
    if has("certexpired") || has("expired") || has("not valid after") {
        return Some(
            "certificate expired — the server cert (or an intermediate) is past its notAfter; renew/reissue it.".to_string(),
        );
    }
    // 이름 불일치.
    if has("notvalidforname")
        || has("not valid for name")
        || has("name mismatch")
        || has("hostname")
    {
        return Some(
            "certificate not valid for this hostname — check the cert SAN/CN against the URL host (or fix Host/SNI).".to_string(),
        );
    }
    // 폐기.
    if has("revoked") || has("revocation") {
        return Some(
            "certificate revoked — reissue the certificate; the client checked CRL/OCSP."
                .to_string(),
        );
    }
    // 신뢰되지 않는 발급자 / 불완전 체인. UnknownIssuer는 self-signed/untrusted/체인 누락을 포괄.
    if has("self signed") || has("self-signed") || has("selfsigned") {
        return Some(
            "self-signed certificate — add the CA to the trust store or use --insecure for testing.".to_string(),
        );
    }
    if has("unknownca")
        || has("unknown ca")
        || has("untrusted")
        || has("unable to get local issuer")
    {
        return Some(
            "issuer not trusted — install the missing intermediate or add the root CA to the trust store.".to_string(),
        );
    }
    if has("unknownissuer") || has("unknown issuer") || has("incomplete") {
        // rustls는 "중간 인증서 누락"과 "신뢰되지 않는 루트"를 모두 UnknownIssuer로 보고하므로
        // 둘 다 짚어준다 (문자열만으로는 구분 불가).
        return Some(
            "issuer not trusted or chain incomplete — install the missing intermediate, or add the root CA to the trust store.".to_string(),
        );
    }
    // SNI 누락.
    if has("no server name") || has("missing_extension") || has("sni") {
        return Some("server requires SNI — connect by hostname, not by raw IP.".to_string());
    }
    // 프로토콜 버전 거부. rustls/OpenSSL은 알림을 밑줄 표기로도 낸다(protocol_version 등).
    if has("protocol version")
        || has("protocolversion")
        || has("protocol_version")
        || has("legacy")
        || has("tls1")
        || has("handshakefailure")
        || has("handshake failure")
        || has("handshake_failure")
    {
        return Some(
            "TLS version/handshake refused — the server may enforce a newer floor (e.g. TLS 1.2+) or a cipher you don't offer.".to_string(),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    /// 테스트용 CertInfo 빌더 (필수 필드만 지정, 나머지는 기본).
    fn cert(subject: &str, issuer: &str, days: i64, is_ca: bool) -> CertInfo {
        CertInfo {
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            san: Vec::new(),
            not_before: DateTime::<Utc>::UNIX_EPOCH,
            not_after: DateTime::<Utc>::UNIX_EPOCH,
            days_remaining: days,
            serial: String::new(),
            sig_alg: String::new(),
            pubkey: String::new(),
            is_ca,
            spki_sha256: String::new(),
            aia_ca_issuers: None,
        }
    }

    // --- cn_of ---

    #[test]
    fn cn_of_extracts_common_name() {
        assert_eq!(cn_of("CN=example.com, O=Foo, C=US"), "example.com");
        assert_eq!(cn_of("CN=example.com,O=Foo"), "example.com");
        // CN이 마지막 RDN인 경우.
        assert_eq!(cn_of("O=Foo, CN=leaf.test"), "leaf.test");
    }

    #[test]
    fn cn_of_falls_back_to_subject_when_no_cn() {
        assert_eq!(cn_of("O=Foo, C=US"), "O=Foo, C=US");
        assert_eq!(cn_of(""), "");
    }

    #[test]
    fn cn_of_tolerates_spaces_around_equals() {
        // RFC2253-ish 인코더가 등호 주위에 공백을 넣는 경우.
        assert_eq!(cn_of("CN = spaced.example"), "spaced.example");
        assert_eq!(cn_of("O = Foo, CN = leaf.test"), "leaf.test");
        // 값이 CN으로 시작하는 다른 속성은 오인하지 않는다.
        assert_eq!(cn_of("O=CN Corp"), "O=CN Corp");
    }

    // --- analyze ---

    #[test]
    fn analyze_empty_chain_is_safe() {
        let a = analyze(&[]);
        assert!(!a.incomplete);
        assert_eq!(a.weakest_days, 0);
        assert_eq!(a.weakest_subject, "");
        assert!(a.aia_repairable.is_none());
        assert!(a.issues.is_empty());
    }

    #[test]
    fn analyze_single_leaf_is_incomplete() {
        // leaf 단독 + 비-CA + 발급자!=주체 => 중간 인증서 누락 추정.
        let chain = vec![cert("CN=leaf.test", "CN=Some Intermediate CA", 90, false)];
        let a = analyze(&chain);
        assert!(a.incomplete);
        assert_eq!(a.weakest_days, 90);
        assert_eq!(a.weakest_subject, "leaf.test");
        assert!(
            a.issues
                .iter()
                .any(|s| s.contains("intermediate certificate(s) missing")),
            "issues={:?}",
            a.issues
        );
    }

    #[test]
    fn analyze_self_signed_single_cert_not_incomplete() {
        // 자가서명(issuer==subject)이면 누락으로 보지 않는다.
        let chain = vec![cert("CN=root", "CN=root", 365, true)];
        let a = analyze(&chain);
        assert!(!a.incomplete);
        assert_eq!(a.weakest_subject, "root");
    }

    #[test]
    fn analyze_flags_intermediate_expiring_before_leaf() {
        // leaf 200d, intermediate 30d => intermediate가 먼저 죽음.
        let chain = vec![
            cert("CN=leaf.test", "CN=Intermediate CA", 200, false),
            cert("CN=Intermediate CA", "CN=Root CA", 30, true),
        ];
        let a = analyze(&chain);
        assert!(!a.incomplete); // 체인이 2장 이상이므로 incomplete 아님.
        assert_eq!(a.weakest_days, 30);
        assert_eq!(a.weakest_subject, "Intermediate CA");
        assert!(
            a.issues
                .iter()
                .any(|s| s.contains("expires before leaf") && s.contains("Intermediate CA")),
            "issues={:?}",
            a.issues
        );
    }

    #[test]
    fn analyze_reports_already_expired_cert() {
        let chain = vec![cert("CN=leaf.test", "CN=Intermediate CA", -3, false)];
        let a = analyze(&chain);
        assert_eq!(a.weakest_days, -3);
        assert!(
            a.issues.iter().any(|s| s.contains("already expired")),
            "issues={:?}",
            a.issues
        );
    }

    #[test]
    fn analyze_flags_chain_order_mismatch() {
        // cert[0].issuer != cert[1].subject => 순서/발급자 불일치.
        let chain = vec![
            cert("CN=leaf.test", "CN=Wrong Issuer", 100, false),
            cert("CN=Real Intermediate", "CN=Root CA", 100, true),
        ];
        let a = analyze(&chain);
        assert!(
            a.issues
                .iter()
                .any(|s| s.contains("chain order/issuer mismatch")),
            "issues={:?}",
            a.issues
        );
    }

    // --- decode_tls_error ---

    #[test]
    fn decode_tls_error_recognizes_expiry() {
        for msg in [
            "invalid peer certificate: Expired",
            "TLS handshake failed: CertExpired",
            "certificate is not valid after 2020-01-01",
        ] {
            let out = decode_tls_error(msg);
            assert!(out.is_some(), "{msg} should decode");
            assert!(out.unwrap().to_lowercase().contains("expired"));
        }
    }

    #[test]
    fn decode_tls_error_recognizes_name_mismatch() {
        let out = decode_tls_error("invalid peer certificate: NotValidForName").unwrap();
        assert!(out.to_lowercase().contains("hostname"));
    }

    #[test]
    fn decode_tls_error_recognizes_unknown_issuer_and_untrusted() {
        // UnknownIssuer는 중간 누락/루트 미신뢰를 모두 포괄하므로 둘 다 언급한다.
        let incomplete = decode_tls_error("invalid peer certificate: UnknownIssuer").unwrap();
        let low = incomplete.to_lowercase();
        assert!(low.contains("intermediate"), "got: {incomplete}");
        assert!(low.contains("trust"), "got: {incomplete}");

        let untrusted = decode_tls_error("the certificate chain is untrusted").unwrap();
        assert!(untrusted.to_lowercase().contains("trust"));
    }

    #[test]
    fn decode_tls_error_recognizes_self_signed() {
        let out = decode_tls_error("self signed certificate in certificate chain").unwrap();
        assert!(out.to_lowercase().contains("self-signed"));
    }

    #[test]
    fn decode_tls_error_recognizes_revocation() {
        let out = decode_tls_error("peer certificate has been revoked (OCSP)").unwrap();
        assert!(out.to_lowercase().contains("revoked"));
    }

    #[test]
    fn decode_tls_error_recognizes_protocol_version() {
        let out = decode_tls_error("peer doesn't support a compatible protocol version").unwrap();
        assert!(out.to_lowercase().contains("tls version"));
    }

    #[test]
    fn decode_tls_error_recognizes_underscore_alerts() {
        // rustls/OpenSSL은 알림을 밑줄 표기로도 낸다.
        for msg in [
            "received fatal alert: protocol_version",
            "received fatal alert: handshake_failure",
        ] {
            let out = decode_tls_error(msg);
            assert!(out.is_some(), "{msg} should decode");
            assert!(out.unwrap().to_lowercase().contains("tls version"));
        }
    }

    #[test]
    fn check_aia_complete_chain_leaves_repairable_none() {
        // 2장 이상 = 완결로 보고 AIA 조회 안 함.
        let chain = vec![
            cert("CN=leaf.test", "CN=Intermediate CA", 90, false),
            cert("CN=Intermediate CA", "CN=Root CA", 200, true),
        ];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = rt.block_on(check_aia(&chain, Duration::from_millis(50)));
        assert!(!a.incomplete);
        assert!(a.aia_repairable.is_none());
    }

    #[test]
    fn check_aia_incomplete_without_url_is_not_repairable() {
        // leaf 단독 + caIssuers URL 없음 => incomplete=true, repairable=Some(false).
        let chain = vec![cert("CN=leaf.test", "CN=Intermediate CA", 90, false)];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = rt.block_on(check_aia(&chain, Duration::from_millis(50)));
        assert!(a.incomplete);
        assert_eq!(a.aia_repairable, Some(false));
    }

    #[test]
    fn decode_tls_error_returns_none_for_unrecognized() {
        assert!(decode_tls_error("connection reset by peer").is_none());
        assert!(decode_tls_error("").is_none());
    }

    // --- base64 / PEM 헬퍼 ---

    #[test]
    fn base64_decode_roundtrip_basic() {
        // "Man" => "TWFu", "Ma" => "TWE=", "M" => "TQ=="
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        // 공백/개행 허용.
        assert_eq!(base64_decode("TW\nFu").unwrap(), b"Man");
    }
}
