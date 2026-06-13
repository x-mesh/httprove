//! `--cert-check` 모드: 여러 도메인의 TLS 인증서 만료를 일괄 점검한다.
//!
//! ## 대상 표기 (targets의 각 항목)
//! - "host" → host:443
//! - "host:port"
//! - URL ("https://host[:port]/...") → 호스트/포트 추출 (http URL은 에러 행으로)
//! - "@path" → 파일에서 한 줄당 하나씩 읽음 (trim, 빈 줄/#주석 스킵, 재귀 @ 없음)
//!
//! ## 동작
//! - probe::fetch_cert(host, port, timeout, insecure)를 tokio::task::JoinSet으로
//!   동시 실행 (동시성 상한 16). 검증 핸드셰이크가 인증서 만료로 실패하면
//!   무검증으로 1회 재시도해 체인을 수집한다 (-k 없이도 EXPIRED 분류 가능).
//! - 결과 테이블: days_remaining 오름차순(에러 행이 맨 위), 컬럼:
//!   STATUS(ERROR 빨강 / EXPIRED 빨강 / WARN 노랑(days < warn_days) / OK 초록),
//!   HOST(host:port), DAYS, EXPIRES(YYYY-MM-DD), ISSUER(CN만).
//!   에러 행은 DAYS/EXPIRES/ISSUER 대신 에러 메시지.
//! - color=false면 색상 없이.
//! - json=true면 테이블 대신 JSON 배열 한 줄:
//!   [{"host":"a.com","port":443,"days_remaining":78,"not_after":"...","issuer":"...",
//!   "subject":"...","error":null}, ...] (에러 시 error에 메시지, 나머지 null)
//! - 종료 코드: 연결 에러 또는 EXPIRED(days<0)가 하나라도 있으면 1, 아니면 0
//!   (WARN은 0 — 경고 표시용).
//!
//! ## 출력 예
//! ```text
//! STATUS   HOST                      DAYS  EXPIRES     ISSUER
//! EXPIRED  expired.badssl.com:443   -4079  2015-04-12  COMODO RSA DV...
//! WARN     soon.example.com:443        12  2026-06-25  R3
//! OK       example.com:443             78  2026-08-29  Cloudflare TLS...
//! ```

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use colored::{ColoredString, Colorize};
use serde::Serialize;
use tokio::task::JoinSet;
use url::Url;

/// fetch_cert 동시 실행 상한.
const MAX_CONCURRENCY: usize = 16;
/// 포트 미지정 시 기본 HTTPS 포트.
const DEFAULT_PORT: u16 = 443;
/// HOST 컬럼 최소 폭 ("HOST" 헤더 길이).
const HOST_MIN_WIDTH: usize = 4;
/// DAYS 컬럼 최소 폭 (부호 포함 자릿수 + 헤더 여백).
const DAYS_MIN_WIDTH: usize = 6;
/// STATUS 컬럼 폭 ("EXPIRED" + 2칸 간격).
const STATUS_WIDTH: usize = 9;

/// 파싱된 점검 대상 1건. 잘못된 표기는 버리지 않고 에러 행으로 보존한다.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// 정상 파싱: 연결할 호스트/포트.
    Host { host: String, port: u16 },
    /// 파싱 실패: 원문 표기와 사유 (결과 테이블의 에러 행이 된다).
    Invalid { spec: String, reason: String },
}

/// 성공한 점검의 leaf 인증서 요약.
struct LeafSummary {
    days_remaining: i64,
    not_after: DateTime<Utc>,
    issuer: String,
    subject: String,
}

/// 결과 테이블 한 행.
struct CheckRow {
    /// HOST 컬럼 표시값 ("host:port", 잘못된 표기는 원문 그대로).
    display: String,
    host: String,
    /// 잘못된 표기는 0 (연결 시도 없음).
    port: u16,
    outcome: Result<LeafSummary, String>,
}

/// JSON 모드 한 행. None 필드는 null로 직렬화된다.
#[derive(Serialize)]
struct JsonRow<'a> {
    host: &'a str,
    port: u16,
    days_remaining: Option<i64>,
    not_after: Option<&'a DateTime<Utc>>,
    issuer: Option<&'a str>,
    subject: Option<&'a str>,
    error: Option<&'a str>,
}

/// cert-check 모드 실행. targets는 CLI 위치 인자 그대로.
pub async fn run_cert_check(
    targets: Vec<String>,
    timeout: Duration,
    insecure: bool,
    warn_days: i64,
    json: bool,
    color: bool,
) -> anyhow::Result<ExitCode> {
    let parsed = expand_targets(&targets)?;
    if parsed.is_empty() {
        bail!("no cert-check targets (the @file may contain only comments/blank lines)");
    }

    // 잘못된 표기는 즉시 에러 행으로, 정상 표기는 실행 큐로 분리한다.
    let mut rows: Vec<CheckRow> = Vec::with_capacity(parsed.len());
    let mut queue: Vec<(String, u16)> = Vec::new();
    for target in parsed {
        match target {
            Target::Host { host, port } => queue.push((host, port)),
            Target::Invalid { spec, reason } => rows.push(CheckRow {
                display: spec.clone(),
                host: spec,
                port: 0,
                outcome: Err(reason),
            }),
        }
    }

    // JoinSet으로 동시 실행 (상한 MAX_CONCURRENCY — 다 차면 하나 끝날 때마다 보충).
    // 태스크 id → 대상 매핑을 들고 있어, 만약 태스크가 JoinError로 끝나도
    // 어떤 대상이었는지 복원해 에러 행으로 보고할 수 있다.
    let mut join_set: JoinSet<Result<LeafSummary, String>> = JoinSet::new();
    let mut inflight: HashMap<tokio::task::Id, (String, u16)> = HashMap::new();
    let mut pending = queue.into_iter();

    for _ in 0..MAX_CONCURRENCY {
        let Some((host, port)) = pending.next() else {
            break;
        };
        let handle = join_set.spawn(check_one(host.clone(), port, timeout, insecure));
        inflight.insert(handle.id(), (host, port));
    }

    while let Some(joined) = join_set.join_next_with_id().await {
        let (id, outcome) = match joined {
            Ok((id, outcome)) => (id, outcome),
            // fetch_cert는 패닉하지 않는 계약이지만, 방어적으로 에러 행으로 변환한다.
            Err(e) => {
                let id = e.id();
                (id, Err(format!("internal: worker task failed: {e}")))
            }
        };
        // inflight에 없을 수는 없지만, 만약을 위해 자리 표시 값으로 대체한다.
        let (host, port) = inflight
            .remove(&id)
            .unwrap_or_else(|| ("unknown".to_string(), 0));
        rows.push(CheckRow {
            display: display_target(&host, port),
            host,
            port,
            outcome,
        });

        // 빈 슬롯에 다음 대상을 보충한다.
        if let Some((host, port)) = pending.next() {
            let handle = join_set.spawn(check_one(host.clone(), port, timeout, insecure));
            inflight.insert(handle.id(), (host, port));
        }
    }

    sort_rows(&mut rows);

    if json {
        let json_rows: Vec<JsonRow<'_>> = rows
            .iter()
            .map(|r| match &r.outcome {
                Ok(s) => JsonRow {
                    host: &r.host,
                    port: r.port,
                    days_remaining: Some(s.days_remaining),
                    not_after: Some(&s.not_after),
                    issuer: Some(&s.issuer),
                    subject: Some(&s.subject),
                    error: None,
                },
                Err(e) => JsonRow {
                    host: &r.host,
                    port: r.port,
                    days_remaining: None,
                    not_after: None,
                    issuer: None,
                    subject: None,
                    error: Some(e),
                },
            })
            .collect();
        let line =
            serde_json::to_string(&json_rows).context("failed to serialize cert-check results")?;
        println!("{line}");
    } else {
        print_table(&rows, warn_days, color);
    }

    // 종료 코드: 에러 행 또는 만료(days < 0)가 하나라도 있으면 1.
    let has_failure = rows.iter().any(|r| match &r.outcome {
        Err(_) => true,
        Ok(s) => s.days_remaining < 0,
    });
    Ok(if has_failure {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// 대상 1건 점검: TLS 핸드셰이크로 체인을 받아 leaf 인증서를 요약한다.
///
/// 검증 핸드셰이크가 "인증서 만료"로 실패하면 무검증으로 1회 재시도해 체인을
/// 수집한다 — 만료 인증서를 ERROR(연결 실패)가 아닌 EXPIRED(음수 DAYS)로
/// 분류하기 위함이다. 그 외 검증/네트워크 실패는 그대로 ERROR 행이 된다.
async fn check_one(
    host: String,
    port: u16,
    timeout: Duration,
    insecure: bool,
) -> Result<LeafSummary, String> {
    let (_tls, chain) = match crate::probe::fetch_cert(&host, port, timeout, insecure).await {
        Ok(pair) => pair,
        Err(e) if !insecure && is_expired_cert_error(&e) => {
            match crate::probe::fetch_cert(&host, port, timeout, true).await {
                Ok(pair) => pair,
                // 재시도도 실패 — 원래 검증 에러가 더 정보가 많으므로 그걸 보고.
                Err(_) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };
    // 체인은 leaf 먼저 — 첫 인증서가 leaf다.
    let leaf = chain
        .into_iter()
        .next()
        .ok_or_else(|| "server presented no certificate".to_string())?;
    Ok(LeafSummary {
        days_remaining: leaf.days_remaining,
        not_after: leaf.not_after,
        issuer: leaf.issuer,
        subject: leaf.subject,
    })
}

/// rustls 검증 에러 메시지가 인증서 만료를 가리키는지.
/// (rustls 0.23: `CertificateError::Expired{,Context}` → "certificate expired").
fn is_expired_cert_error(message: &str) -> bool {
    message.contains("certificate expired") || message.contains("CertExpired")
}

// ---------------------------------------------------------------------------
// 대상 표기 파싱
// ---------------------------------------------------------------------------

/// CLI 대상 목록을 파싱하고 "@path" 항목을 파일 내용으로 확장한다.
/// 파일 읽기 실패는 하드 에러, 개별 표기 오류는 Target::Invalid로 보존한다.
fn expand_targets(specs: &[String]) -> anyhow::Result<Vec<Target>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let spec = spec.trim();
        if let Some(path) = spec.strip_prefix('@') {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read target file: {path}"))?;
            for line in content.lines() {
                let line = line.trim();
                // 빈 줄과 # 주석은 건너뛴다.
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // 파일 안의 @는 재귀 확장하지 않는다 — 에러 행으로 보고.
                if line.starts_with('@') {
                    out.push(Target::Invalid {
                        spec: line.to_string(),
                        reason: "nested @file is not supported".to_string(),
                    });
                    continue;
                }
                out.push(parse_target_spec(line));
            }
        } else {
            out.push(parse_target_spec(spec));
        }
    }
    Ok(out)
}

/// 단일 대상 표기를 파싱한다: "host" | "host:port" | https URL.
/// 스킴이 없으면 https://를 가정해 url 크레이트 하나로 검증을 통일한다.
fn parse_target_spec(spec: &str) -> Target {
    let invalid = |reason: String| Target::Invalid {
        spec: spec.to_string(),
        reason,
    };

    if spec.is_empty() {
        return invalid("empty target".to_string());
    }

    let url_text = if spec.contains("://") {
        spec.to_string()
    } else {
        format!("https://{spec}")
    };
    let url = match Url::parse(&url_text) {
        Ok(u) => u,
        Err(e) => return invalid(format!("invalid target: {e}")),
    };
    match url.scheme() {
        "https" => {}
        "http" => return invalid("http URL has no TLS certificate (use https)".to_string()),
        other => return invalid(format!("unsupported scheme: {other}")),
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        // IPv6 리터럴은 대괄호 없는 베어 주소로 저장한다 — fetch_cert의
        // IpAddr 파싱/SNI/DNS lookup 모두 베어 형태를 요구한다.
        // 표시용 "[::1]:443" 표기는 display_target이 다시 만든다.
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => return invalid("target has no host".to_string()),
    };
    Target::Host {
        host,
        port: url.port().unwrap_or(DEFAULT_PORT),
    }
}

/// HOST 컬럼 표기: IPv6 베어 주소는 대괄호로 감싼다 ("[::1]:443").
fn display_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ---------------------------------------------------------------------------
// 출력
// ---------------------------------------------------------------------------

/// days_remaining 오름차순, 에러 행이 맨 위. 동률은 표시 이름으로 안정화한다.
fn sort_rows(rows: &mut [CheckRow]) {
    fn key(row: &CheckRow) -> (u8, i64) {
        match &row.outcome {
            Err(_) => (0, i64::MIN),
            Ok(s) => (1, s.days_remaining),
        }
    }
    rows.sort_by(|a, b| key(a).cmp(&key(b)).then_with(|| a.display.cmp(&b.display)));
}

/// color 게이트를 거쳐 색을 적용한다. 비활성 시 원문 그대로.
fn paint(s: &str, enabled: bool, f: impl FnOnce(&str) -> ColoredString) -> String {
    if enabled {
        f(s).to_string()
    } else {
        s.to_string()
    }
}

/// 고정폭 컬럼 테이블 출력. 색상은 패딩 후 적용해 컬럼 폭이 틀어지지 않게 한다.
fn print_table(rows: &[CheckRow], warn_days: i64, color: bool) {
    // HOST/DAYS 폭은 내용에 맞춰 동적으로 (최소 폭은 헤더 기준).
    let host_w = rows
        .iter()
        .map(|r| r.display.len())
        .chain([HOST_MIN_WIDTH])
        .max()
        .unwrap_or(HOST_MIN_WIDTH);
    let days_w = rows
        .iter()
        .filter_map(|r| r.outcome.as_ref().ok())
        .map(|s| s.days_remaining.to_string().len())
        .chain([DAYS_MIN_WIDTH])
        .max()
        .unwrap_or(DAYS_MIN_WIDTH);

    println!(
        "{:<sw$}{:<host_w$}  {:>days_w$}  {:<10}  ISSUER",
        "STATUS",
        "HOST",
        "DAYS",
        "EXPIRES",
        sw = STATUS_WIDTH,
    );

    for row in rows {
        match &row.outcome {
            Err(msg) => {
                // 에러 행: DAYS/EXPIRES/ISSUER 자리에 에러 메시지.
                let status = paint(&format!("{:<STATUS_WIDTH$}", "ERROR"), color, |s| {
                    s.red().bold()
                });
                println!("{status}{:<host_w$}  {msg}", row.display);
            }
            Ok(s) => {
                let (word, painter): (&str, fn(&str) -> ColoredString) = if s.days_remaining < 0 {
                    ("EXPIRED", |t| t.red().bold())
                } else if s.days_remaining < warn_days {
                    ("WARN", |t| t.yellow())
                } else {
                    ("OK", |t| t.green())
                };
                let status = paint(&format!("{word:<STATUS_WIDTH$}"), color, painter);
                let expires = s.not_after.format("%Y-%m-%d").to_string();
                println!(
                    "{status}{:<host_w$}  {:>days_w$}  {expires:<10}  {}",
                    row.display,
                    s.days_remaining,
                    extract_cn(&s.issuer),
                );
            }
        }
    }
}

/// RFC 2253 스타일 DN 문자열에서 CN만 추출한다. 없으면 전체를 반환.
fn extract_cn(dn: &str) -> String {
    dn.split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("CN="))
        .unwrap_or(dn)
        .to_string()
}

// ---------------------------------------------------------------------------
// 테스트
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 테스트용 임시 파일. drop 시 삭제된다.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn create(name: &str, content: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("httprove_cert_check_{}_{name}", std::process::id()));
            std::fs::write(&path, content).expect("failed to write temp file");
            TempFile(path)
        }

        fn path_str(&self) -> &str {
            self.0.to_str().expect("temp path is not utf-8")
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn host(h: &str, p: u16) -> Target {
        Target::Host {
            host: h.to_string(),
            port: p,
        }
    }

    #[test]
    fn parse_bare_host_defaults_to_443() {
        assert_eq!(parse_target_spec("example.com"), host("example.com", 443));
    }

    #[test]
    fn parse_host_with_port() {
        assert_eq!(
            parse_target_spec("example.com:8443"),
            host("example.com", 8443)
        );
    }

    #[test]
    fn parse_ipv4_and_ipv6_literals() {
        assert_eq!(parse_target_spec("192.0.2.1:9443"), host("192.0.2.1", 9443));
        // IPv6은 연결/SNI에 쓸 수 있는 베어 주소로 저장된다 (대괄호 제거).
        assert_eq!(parse_target_spec("[::1]:8443"), host("::1", 8443));
        assert_eq!(parse_target_spec("[2001:db8::1]"), host("2001:db8::1", 443));
    }

    #[test]
    fn display_target_rebrackets_ipv6() {
        assert_eq!(display_target("example.com", 443), "example.com:443");
        assert_eq!(display_target("192.0.2.1", 9443), "192.0.2.1:9443");
        assert_eq!(display_target("::1", 8443), "[::1]:8443");
    }

    #[test]
    fn parse_https_url_extracts_host_and_port() {
        assert_eq!(
            parse_target_spec("https://example.com:9443/health?x=1"),
            host("example.com", 9443)
        );
        assert_eq!(
            parse_target_spec("https://example.com/path"),
            host("example.com", 443)
        );
    }

    #[test]
    fn parse_http_url_is_error_row() {
        assert!(matches!(
            parse_target_spec("http://example.com"),
            Target::Invalid { ref spec, .. } if spec == "http://example.com"
        ));
    }

    #[test]
    fn parse_unsupported_scheme_is_error_row() {
        assert!(matches!(
            parse_target_spec("ftp://example.com"),
            Target::Invalid { .. }
        ));
    }

    #[test]
    fn parse_garbage_is_error_row() {
        assert!(matches!(
            parse_target_spec("exa mple"),
            Target::Invalid { .. }
        ));
        assert!(matches!(parse_target_spec(""), Target::Invalid { .. }));
        assert!(matches!(
            parse_target_spec("example.com:notaport"),
            Target::Invalid { .. }
        ));
    }

    #[test]
    fn expand_at_file_skips_comments_and_blank_lines() {
        let file = TempFile::create(
            "targets.txt",
            "# comment line\n\nexample.com\n  other.example.com:8443  \n\
             https://third.example.com:9443/health\n   # indented comment\n",
        );
        let specs = vec![format!("@{}", file.path_str())];
        let targets = expand_targets(&specs).expect("expand should succeed");
        assert_eq!(
            targets,
            vec![
                host("example.com", 443),
                host("other.example.com", 8443),
                host("third.example.com", 9443),
            ]
        );
    }

    #[test]
    fn expand_mixes_cli_specs_and_file() {
        let file = TempFile::create("mixed.txt", "a.example.com\n");
        let specs = vec![
            "b.example.com:444".to_string(),
            format!("@{}", file.path_str()),
        ];
        let targets = expand_targets(&specs).expect("expand should succeed");
        assert_eq!(
            targets,
            vec![host("b.example.com", 444), host("a.example.com", 443)]
        );
    }

    #[test]
    fn expand_nested_at_file_is_error_row() {
        let file = TempFile::create("nested.txt", "@another-file.txt\nexample.com\n");
        let specs = vec![format!("@{}", file.path_str())];
        let targets = expand_targets(&specs).expect("expand should succeed");
        assert_eq!(targets.len(), 2);
        assert!(matches!(
            targets[0],
            Target::Invalid { ref spec, .. } if spec == "@another-file.txt"
        ));
        assert_eq!(targets[1], host("example.com", 443));
    }

    #[test]
    fn expand_missing_file_is_hard_error() {
        let specs = vec!["@/nonexistent/httprove-cert-check-test".to_string()];
        assert!(expand_targets(&specs).is_err());
    }

    #[test]
    fn sort_puts_errors_first_then_days_ascending() {
        let mk = |display: &str, outcome: Result<i64, &str>| CheckRow {
            display: display.to_string(),
            host: display.to_string(),
            port: 443,
            outcome: outcome
                .map(|days| LeafSummary {
                    days_remaining: days,
                    not_after: Utc::now(),
                    issuer: "CN=Test CA".to_string(),
                    subject: "CN=test".to_string(),
                })
                .map_err(str::to_string),
        };
        let mut rows = vec![
            mk("ok.example.com:443", Ok(78)),
            mk("warn.example.com:443", Ok(12)),
            mk("err.example.com:443", Err("connect failed")),
            mk("expired.example.com:443", Ok(-4079)),
        ];
        sort_rows(&mut rows);
        let order: Vec<&str> = rows.iter().map(|r| r.display.as_str()).collect();
        assert_eq!(
            order,
            vec![
                "err.example.com:443",
                "expired.example.com:443",
                "warn.example.com:443",
                "ok.example.com:443",
            ]
        );
    }

    #[test]
    fn extract_cn_finds_cn_or_falls_back() {
        assert_eq!(extract_cn("C=US, O=Let's Encrypt, CN=R3"), "R3");
        assert_eq!(extract_cn("O=No CN Here"), "O=No CN Here");
    }
}
