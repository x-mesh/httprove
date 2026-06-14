//! 시스템 traceroute 연동 — 네트워크 경로 표시 + TLS 종단 hop 주석.
//!
//! 담당 기능:
//! - ⑫ 시스템에 설치된 `traceroute`(macOS/Linux)를 호출해 URL 호스트까지의 경로를 보여주고,
//!   일반 TLS 프로브로 실제 연결된 IP를 알아내 어느 hop이 TLS 종단 엔드포인트인지 표시한다.
//!
//! raw 소켓을 쓰지 않으므로 root 권한이 필요 없다(시스템 traceroute에 위임).
//!
//! ## run_trace(cfg, color) -> Result<ExitCode>
//! 1. `traceroute` 바이너리 존재 확인. 없으면 명확한 에러 메시지 출력 후 ExitCode::from(1).
//!    (which/where 대신, Command 실행 실패(NotFound)를 잡아 처리해도 된다.)
//! 2. URL 호스트를 대상으로 `tokio::process::Command`로 traceroute 실행.
//!    - macOS/Linux 공통으로 동작하도록 인자는 보수적으로: 호스트명만 전달(예: `traceroute <host>`).
//!      필요하면 `-n`(숫자 표시), `-w`(대기), `-q`(쿼리 수), `-m`(최대 hop) 등 안전한 옵션 추가 가능.
//!    - stdout을 캡처해 hop 라인을 파싱한다:
//!      "hop#  host (ip)  rtt1 ms  rtt2 ms ..." / 무응답은 "*".
//!      hop 번호, 호스트, IP, 대표 RTT(첫 유효 값 또는 평균)를 뽑는다.
//! 3. 같은 호스트로 일반 TLS 프로브(crate::probe::probe, cfg 그대로)를 1회 수행해
//!    연결 IP(final_hop().ip)를 얻는다.
//! 4. hop 목록을 출력하고, 연결 IP와 일치하는 hop(목적지)을 "← TLS endpoint"로 마크한다.
//!    프로브가 실패하면 경로만 출력하고 종단 표기는 생략(또는 실패 사유 표기).
//!
//! 종료 코드: traceroute 실행 자체가 실패(바이너리 없음/스폰 실패)면 1, 그 외엔 SUCCESS
//! (traceroute가 일부 hop을 못 찍어도 정보 제공이므로 0).
//!
//! ## 구현 메모
//! - 패닉 금지. Command 출력은 UTF-8 손실 허용(from_utf8_lossy)으로 파싱.
//! - 파서는 공백 분할 + 괄호 안 IP 추출 정도로 견고하게. 줄 형식이 어긋나면 그 줄은 건너뛴다.
//! - 호스트 추출은 cfg.url.host_str()을 사용(없으면 에러).
//! - hop 파싱 함수를 별도로 빼고 #[cfg(test)]로 샘플 출력 1~2줄을 검증하면 좋다.

use std::net::IpAddr;
use std::process::ExitCode;

use anyhow::{Context, bail};
use colored::{ColoredString, Colorize};

use crate::types::ProbeConfig;

/// traceroute 1회의 보수적 기본 옵션. macOS/Linux 공통으로 안전한 값만 사용한다.
/// -w: 응답 대기(초), -q: hop당 쿼리 수, -m: 최대 hop 수.
const WAIT_SECS: &str = "2";
const QUERIES: &str = "2";
const MAX_HOPS: &str = "30";

/// 파싱된 traceroute hop 1줄. 무응답("* * *") hop은 ip=None, rtt_ms=None.
#[derive(Debug, Clone, PartialEq)]
struct TraceHop {
    /// hop 번호 (TTL).
    ttl: u32,
    /// 표시용 호스트명. `-n` 출력이거나 역방향 조회 실패 시 IP 문자열이 된다.
    /// 무응답 hop은 None.
    host: Option<String>,
    /// 응답한 첫 IP. 무응답 hop은 None.
    ip: Option<IpAddr>,
    /// 대표 RTT (첫 유효 측정값, ms). 무응답 hop은 None.
    rtt_ms: Option<f64>,
}

/// 시스템 traceroute로 경로를 표시하고 TLS 종단 hop을 주석한다.
pub async fn run_trace(cfg: &ProbeConfig, color: bool) -> anyhow::Result<ExitCode> {
    // 대상 호스트 (traceroute는 호스트명/IP만 받고 스킴/경로는 무시).
    let host = cfg
        .url
        .host_str()
        .context("trace target URL has no host")?
        .to_string();

    // --- traceroute 실행 -----------------------------------------------------
    // 바이너리 부재(NotFound)는 raw 소켓 폴백 없이 명확한 에러로 종료한다.
    let output = match run_traceroute(&host).await {
        Ok(out) => out,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                bail!(
                    "`traceroute` command not found. Install it (macOS: preinstalled; \
                     Debian/Ubuntu: `apt install traceroute`) and retry."
                );
            }
            return Err(
                anyhow::Error::new(e).context(format!("failed to run traceroute for {host}"))
            );
        }
    };

    // stdout/stderr 모두 손실 허용 디코드. traceroute는 헤더/경고를 stderr에 쓰기도 한다.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hops = parse_hops(&stdout);

    // traceroute가 한 줄도 못 냈다면(권한/네트워크 등) stderr를 사유로 보여준다.
    if hops.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = first_nonempty_line(&stderr).unwrap_or("no route information produced");
        bail!("traceroute produced no hops for {host}: {detail}");
    }

    // --- TLS 프로브로 종단(연결) IP 확인 -------------------------------------
    // 경로만으로는 어느 hop이 실제 서비스 엔드포인트인지 알 수 없으므로 일반 프로브를
    // 1회 수행해 연결 IP와 TLS POP 정보를 얻는다. 실패해도 경로는 그대로 출력한다.
    let result = crate::probe::probe(cfg, 0).await;
    let endpoint = result.final_hop().map(|h| h.ip);
    let tls_label = result
        .final_hop()
        .and_then(|h| h.tls.as_ref())
        .map(|t| match &t.alpn {
            Some(alpn) => format!("{} {}", t.version, alpn),
            None => t.version.clone(),
        });
    let probe_error = result.error.as_ref().map(|e| e.message.clone());

    print_hops(&host, &hops, endpoint, tls_label.as_deref(), color);

    // 종단(연결 IP)이 경로상에 나타나지 않았으면 한 줄로 알린다 (anycast/방화벽 등으로
    // 마지막 hop이 누락되는 흔한 상황). 프로브 실패 사유도 함께 보여준다.
    print_endpoint_footer(endpoint, &hops, probe_error.as_deref(), color);

    // traceroute가 일부 hop을 못 찍어도 정보 제공이므로 성공 종료.
    Ok(ExitCode::SUCCESS)
}

/// traceroute 자식 프로세스를 실행하고 출력을 수집한다.
/// 바이너리 부재는 호출자가 ErrorKind::NotFound로 식별한다.
///
/// tokio의 `process` 피처가 빌드에 포함되어 있지 않으므로 블로킹
/// `std::process::Command`를 `spawn_blocking`으로 감싸 런타임을 막지 않게 한다.
/// traceroute는 한 번만 돌리는 일회성 자식 프로세스라 이 방식이 충분하다.
async fn run_traceroute(host: &str) -> std::io::Result<std::process::Output> {
    let host = host.to_string();
    let join = tokio::task::spawn_blocking(move || {
        // 인자는 macOS/Linux 공통으로 안전한 것만: -w 대기, -q 쿼리 수, -m 최대 hop.
        // 호스트명을 그대로 넘겨 역방향 조회 결과(host (ip))까지 받는다 (-n 미사용).
        std::process::Command::new("traceroute")
            .arg("-w")
            .arg(WAIT_SECS)
            .arg("-q")
            .arg(QUERIES)
            .arg("-m")
            .arg(MAX_HOPS)
            .arg("--")
            .arg(&host)
            .output()
    })
    .await;
    match join {
        Ok(result) => result,
        // spawn_blocking 태스크가 패닉/취소된 경우 — io 에러로 변환해 전파한다.
        Err(e) => Err(std::io::Error::other(format!(
            "traceroute worker task failed: {e}"
        ))),
    }
}

/// traceroute stdout 전체를 파싱해 hop 목록을 만든다.
///
/// 인식하는 줄:
/// - "<n>  host (ip)  <rtt> ms ..." — 응답 hop (host는 -n이면 IP 문자열).
/// - "<n>  ip  <rtt> ms ..."        — `-n` 출력의 베어 IP 형태.
/// - "<n>  * * *"                   — 무응답 hop (ip/rtt = None).
/// - "    host (ip) ..." (선행 hop 번호 없음) — 같은 hop의 추가 응답(연속 줄)이므로 무시.
///
/// 헤더("traceroute to ...")·경고 줄은 hop 번호로 시작하지 않으므로 자연히 건너뛴다.
fn parse_hops(stdout: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in stdout.lines() {
        // 첫 토큰이 hop 번호인 줄만 새 hop으로 인식한다. 연속 줄(추가 IP)이나
        // 헤더/경고 줄은 숫자로 시작하지 않으므로 None이 되어 건너뛴다.
        if let Some(hop) = parse_hop_line(line) {
            hops.push(hop);
        }
    }
    hops
}

/// traceroute 한 줄을 파싱한다. hop 번호로 시작하지 않으면 None.
fn parse_hop_line(line: &str) -> Option<TraceHop> {
    let mut tokens = line.split_whitespace();
    // 첫 토큰이 hop 번호여야 한다 (연속 줄/헤더 배제).
    let ttl: u32 = tokens.next()?.parse().ok()?;

    let rest: Vec<&str> = tokens.collect();
    // "* * *" 또는 "*" → 무응답 hop.
    if rest.is_empty() || rest.iter().all(|t| *t == "*") {
        return Some(TraceHop {
            ttl,
            host: None,
            ip: None,
            rtt_ms: None,
        });
    }

    let (host, ip) = parse_host_ip(&rest);
    let rtt_ms = parse_first_rtt(&rest);
    Some(TraceHop {
        ttl,
        host,
        ip,
        rtt_ms,
    })
}

/// hop 토큰들에서 호스트명과 IP를 뽑는다.
/// - "host (1.2.3.4)" 형태: host=host, ip=1.2.3.4.
/// - "1.2.3.4" 형태(`-n`): host=ip 문자열, ip=1.2.3.4.
///
/// 첫 응답만 본다 (다중 쿼리의 동일 호스트 가정).
fn parse_host_ip(tokens: &[&str]) -> (Option<String>, Option<IpAddr>) {
    let first = match tokens.first() {
        Some(t) => *t,
        None => return (None, None),
    };
    // "*"가 첫 토큰이면(부분 무응답) IP를 못 얻는다.
    if first == "*" {
        return (None, None);
    }

    // 괄호 IP: 두 번째 토큰이 "(ip)" 형태면 그 안의 IP를 사용한다.
    if let Some(paren) = tokens.get(1)
        && let Some(inner) = paren
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .or_else(|| paren.strip_prefix('(').map(|s| s.trim_end_matches(')')))
        && let Ok(ip) = inner.parse::<IpAddr>()
    {
        return (Some(first.to_string()), Some(ip));
    }

    // 베어 IP (`-n` 출력): 첫 토큰 자체가 IP.
    if let Ok(ip) = first.parse::<IpAddr>() {
        return (Some(first.to_string()), Some(ip));
    }

    // IP를 못 찾았지만 호스트명은 있다 (역방향만 나오는 드문 경우).
    (Some(first.to_string()), None)
}

/// 토큰 스트림에서 첫 RTT 값을 찾는다: "<float> ms" 패턴의 float.
fn parse_first_rtt(tokens: &[&str]) -> Option<f64> {
    // "12.512 ms" → 값 토큰 다음에 "ms"가 오는 첫 쌍을 찾는다.
    for pair in tokens.windows(2) {
        if pair[1] == "ms"
            && let Ok(v) = pair[0].parse::<f64>()
        {
            return Some(v);
        }
    }
    None
}

/// 문자열에서 공백이 아닌 첫 줄(trim 후)을 반환한다.
fn first_nonempty_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

// ---------------------------------------------------------------------------
// 출력
// ---------------------------------------------------------------------------

/// HOP 컬럼 폭 (우측 정렬 hop 번호).
const HOP_WIDTH: usize = 3;
/// RTT 컬럼 폭 ("123.4ms" 정도를 우측 정렬).
const RTT_WIDTH: usize = 9;

/// color 게이트를 거쳐 색을 적용한다. 비활성 시 원문 그대로.
/// (cert_check.rs / output::text 와 동일한 헬퍼 패턴.)
fn paint(s: &str, enabled: bool, f: impl FnOnce(&str) -> ColoredString) -> String {
    if enabled {
        f(s).to_string()
    } else {
        s.to_string()
    }
}

/// 파싱한 hop들을 고정폭 테이블로 출력한다. 연결 IP와 일치하는 hop을
/// "← TLS endpoint [<tls>]"로 마크한다. 색상은 패딩 후 적용해 폭이 틀어지지 않게 한다.
fn print_hops(
    host: &str,
    hops: &[TraceHop],
    endpoint: Option<IpAddr>,
    tls_label: Option<&str>,
    color: bool,
) {
    // HOST 컬럼 폭은 내용에 맞춰 동적으로 (최소 폭은 헤더 "HOST" 기준).
    let host_w = hops
        .iter()
        .map(|h| display_host(h).len())
        .chain([4])
        .max()
        .unwrap_or(4);

    println!("traceroute to {host}");
    println!(
        "{:>hw$}  {:<host_w$}  {:>rw$}",
        "HOP",
        "HOST",
        "RTT",
        hw = HOP_WIDTH,
        rw = RTT_WIDTH,
    );

    for hop in hops {
        let ttl = format!("{:>HOP_WIDTH$}", hop.ttl);
        let host_cell = format!("{:<host_w$}", display_host(hop));
        let rtt_cell = match hop.rtt_ms {
            Some(ms) => format!("{:>RTT_WIDTH$}", format!("{ms:.1}ms")),
            None => format!("{:>RTT_WIDTH$}", "*"),
        };

        // 종단(연결 IP) hop이면 강조 + 주석.
        let is_endpoint = matches!((endpoint, hop.ip), (Some(e), Some(ip)) if e == ip);
        if is_endpoint {
            let mark = match tls_label {
                Some(tls) => format!("  {} [{tls}]", "← TLS endpoint"),
                None => "  ← TLS endpoint".to_string(),
            };
            println!(
                "{}  {}  {}{}",
                paint(&ttl, color, |s| s.cyan().bold()),
                paint(&host_cell, color, |s| s.cyan().bold()),
                rtt_cell,
                paint(&mark, color, |s| s.green().bold()),
            );
        } else if hop.ip.is_none() {
            // 무응답 hop은 흐리게.
            println!(
                "{}",
                paint(&format!("{ttl}  {host_cell}  {rtt_cell}"), color, |s| s
                    .dimmed(),)
            );
        } else {
            println!("{ttl}  {host_cell}  {rtt_cell}");
        }
    }
}

/// 종단(연결 IP)이 경로에 안 나타났거나 프로브가 실패한 경우 한 줄 안내를 출력한다.
fn print_endpoint_footer(
    endpoint: Option<IpAddr>,
    hops: &[TraceHop],
    probe_error: Option<&str>,
    color: bool,
) {
    match (endpoint, probe_error) {
        // 프로브 성공 + 연결 IP를 알아냈는데 경로 어디에도 없으면 알린다.
        (Some(ip), None) => {
            let seen = hops.iter().any(|h| h.ip == Some(ip));
            if !seen {
                let note =
                    format!("note: connected endpoint {ip} did not appear in the route above");
                println!("{}", paint(&note, color, |s| s.dimmed()));
            }
        }
        // 프로브 실패 — 경로는 보여주되 종단 표기는 생략하고 사유만 안내한다.
        (_, Some(err)) => {
            let note = format!("note: could not determine TLS endpoint ({err})");
            println!("{}", paint(&note, color, |s| s.yellow()));
        }
        _ => {}
    }
}

/// hop의 HOST 컬럼 표시값. 호스트명이 있으면 그대로, 없으면 IP, 둘 다 없으면 "*".
fn display_host(hop: &TraceHop) -> String {
    if let Some(host) = &hop.host {
        host.clone()
    } else if let Some(ip) = hop.ip {
        ip.to_string()
    } else {
        "*".to_string()
    }
}

// ---------------------------------------------------------------------------
// 테스트
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_host_paren_ip_line() {
        // macOS 형식: "<n>  host (ip)  rtt ms".
        let hop = parse_hop_line(" 1  172.30.1.254 (172.30.1.254)  3.620 ms").unwrap();
        assert_eq!(hop.ttl, 1);
        assert_eq!(hop.host.as_deref(), Some("172.30.1.254"));
        assert_eq!(hop.ip, Some(IpAddr::V4(Ipv4Addr::new(172, 30, 1, 254))));
        assert_eq!(hop.rtt_ms, Some(3.620));
    }

    #[test]
    fn parse_named_host_with_multiple_rtts() {
        // 역방향 조회된 호스트명 + 여러 RTT — 첫 RTT만 대표값으로.
        let line = "5  router.example.net (203.0.113.5)  12.512 ms  10.880 ms  11.001 ms";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.ttl, 5);
        assert_eq!(hop.host.as_deref(), Some("router.example.net"));
        assert_eq!(hop.ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))));
        assert_eq!(hop.rtt_ms, Some(12.512));
    }

    #[test]
    fn parse_numeric_only_line() {
        // `-n` 형식: 베어 IP. host도 IP 문자열로 채운다.
        let hop = parse_hop_line(" 4  112.188.32.109  4.583 ms").unwrap();
        assert_eq!(hop.ttl, 4);
        assert_eq!(hop.host.as_deref(), Some("112.188.32.109"));
        assert_eq!(hop.ip, Some(IpAddr::V4(Ipv4Addr::new(112, 188, 32, 109))));
        assert_eq!(hop.rtt_ms, Some(4.583));
    }

    #[test]
    fn parse_timeout_hop() {
        let hop = parse_hop_line(" 2  * * *").unwrap();
        assert_eq!(hop.ttl, 2);
        assert_eq!(hop.host, None);
        assert_eq!(hop.ip, None);
        assert_eq!(hop.rtt_ms, None);
    }

    #[test]
    fn header_and_warning_lines_are_skipped() {
        // hop 번호로 시작하지 않는 줄은 None.
        assert!(
            parse_hop_line("traceroute to example.com (172.66.147.243), 30 hops max").is_none()
        );
        assert!(
            parse_hop_line("traceroute: Warning: example.com has multiple addresses").is_none()
        );
        // 연속 줄(선행 hop 번호 없는 추가 IP)도 새 hop이 아니므로 None.
        assert!(parse_hop_line("    112.188.44.81 (112.188.44.81)  6.461 ms").is_none());
    }

    #[test]
    fn parse_full_output_collects_hops_and_skips_noise() {
        // 헤더 + 응답 + 무응답 + 연속 줄(추가 IP)을 섞은 실제 형태.
        let sample = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 40 byte packets
 1  172.30.1.254 (172.30.1.254)  2.605 ms  2.404 ms
 2  * * *
 3  112.188.44.149 (112.188.44.149)  4.677 ms
    112.188.44.81 (112.188.44.81)  6.461 ms
 4  8.8.8.8 (8.8.8.8)  9.123 ms
";
        let hops = parse_hops(sample);
        // 헤더와 연속 줄은 제외되고 hop 4개만 남는다.
        assert_eq!(hops.len(), 4);
        assert_eq!(hops[0].ttl, 1);
        assert_eq!(hops[0].ip, Some(IpAddr::V4(Ipv4Addr::new(172, 30, 1, 254))));
        assert_eq!(hops[1].ip, None); // 무응답 hop.
        assert_eq!(hops[2].ttl, 3);
        // 연속 줄(112.188.44.81)은 hop 3에 흡수되지 않고 그냥 버려진다.
        assert_eq!(hops[3].ip, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn parse_partial_star_then_ip() {
        // 일부 쿼리는 무응답("*")이지만 이후에 응답이 온 hop.
        let hop = parse_hop_line(" 7  * 203.0.113.9 (203.0.113.9)  20.5 ms").unwrap();
        assert_eq!(hop.ttl, 7);
        // 첫 토큰이 "*"라 host/ip 추출은 건너뛰지만 hop 자체는 유효하게 보존.
        assert_eq!(hop.host, None);
        assert_eq!(hop.ip, None);
    }

    #[test]
    fn display_host_prefers_name_then_ip_then_star() {
        let named = TraceHop {
            ttl: 1,
            host: Some("r1.example.net".to_string()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            rtt_ms: Some(1.0),
        };
        assert_eq!(display_host(&named), "r1.example.net");

        let ip_only = TraceHop {
            ttl: 2,
            host: None,
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            rtt_ms: Some(2.0),
        };
        assert_eq!(display_host(&ip_only), "10.0.0.2");

        let timeout = TraceHop {
            ttl: 3,
            host: None,
            ip: None,
            rtt_ms: None,
        };
        assert_eq!(display_host(&timeout), "*");
    }

    #[test]
    fn first_nonempty_line_skips_blanks() {
        assert_eq!(first_nonempty_line("\n\n  hello\nworld"), Some("hello"));
        assert_eq!(first_nonempty_line("   \n\t\n"), None);
    }
}
