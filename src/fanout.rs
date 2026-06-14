//! 호스트의 모든 IP로 개별 프로브(per-IP fanout) + IPv4/IPv6 분기 비교.
//!
//! 담당 기능:
//! - ⑨ per-IP fanout: DNS가 반환한 모든 A/AAAA 레코드에 대해 각 IP를 개별 연결로 프로브
//! - ⑪ v4/v6 divergence: -4 강제와 -6 강제를 각각 한 번씩 프로브해 단계별로 나란히 비교
//!
//! ## 핵심 트릭 — 특정 IP로 프로브하기
//! probe.rs는 `cfg.resolve == Some(ip)`이면 DNS를 건너뛰고 그 IP로 직접 연결하되,
//! SNI/Host는 URL 호스트를 그대로 유지한다. 따라서 IP별 프로브는:
//!   let mut c = cfg.clone();
//!   c.resolve = Some(ip);
//!   c.ip_family = IpFamily::Auto;  // resolve가 우선이므로 패밀리는 무관
//!   let r = crate::probe::probe(&c, seq).await;
//! 로 만든다 (probe는 `&ProbeConfig`를 받고 ProbeResult를 돌려줌).
//!
//! ## run_fanout(cfg, color) -> Result<ExitCode>
//! 1. URL 호스트:포트로 `tokio::net::lookup_host`를 호출해 **모든** IP를 모은다.
//!    cfg.ip_family가 V4/V6면 해당 패밀리만 필터, Auto면 전부.
//!    cfg.resolve가 이미 Some이면 그 IP 하나만 대상으로 한다.
//!    주소가 없으면 에러 반환.
//! 2. 각 IP를 위 트릭으로 개별 프로브한다(동시 또는 순차 — 순차로도 충분).
//! 3. IP로 정렬된 표를 출력: `IP | status | ttfb | total | tls`.
//!    - ttfb/total은 summed_timings 기준 ms.
//!    - tls는 TLS 버전(없으면 "-").
//!    - 실패한 IP는 status 자리에 에러 단계 표기.
//! 4. **이상치(outlier) 플래그**: 어떤 IP의 status가 다수와 다르거나,
//!    total이 중앙값의 일정 배수(예: 2x) 이상이면 행 끝에 마크(예: " ⚠ outlier")를 단다.
//! 5. 종료 코드: 실패 IP가 하나라도 있거나 status/latency 이상치가 있으면 ExitCode::from(1),
//!    전부 정상·균일하면 SUCCESS.
//!
//! ## run_all_families(cfg, color) -> Result<ExitCode>
//! - cfg를 두 벌 clone해 하나는 ip_family=V4, 다른 하나는 V6로 강제(resolve는 None으로)하고
//!   각각 1회 프로브한다.
//! - 한쪽 패밀리가 아예 해석 불가하면(해당 레코드 없음) 그 사실을 명시하고 가능한 쪽만 표시.
//! - 단계별(dns/tcp/tls/ttfb/download/total) v4 vs v6 값을 나란히 출력하고,
//!   유의미한 차이(예: 한쪽만 실패, total 차이 큰 경우)를 강조한다.
//! - 종료 코드: 한쪽이라도 실패하면 1, 둘 다 성공이면 SUCCESS.
//!
//! ## 구현 메모
//! - 패닉 금지. lookup_host 실패는 anyhow context로.
//! - 표 정렬은 IpAddr의 정렬 순서(또는 문자열 정렬)로 안정화.
//! - color면 status/이상치를 colored로 강조(빨강/노랑). 비-color는 텍스트 마크만.
//! - 출력 폭은 기존 text.rs 톤과 맞추되 자체적으로 포맷해도 된다.

use std::net::IpAddr;
use std::process::ExitCode;

use anyhow::Context;
use colored::{ColoredString, Colorize};

use crate::types::{IpFamily, PhaseTimings, ProbeConfig, ProbeResult};

/// latency 이상치 판정 배수 — total이 중앙값의 이 배수 이상이면 outlier.
const OUTLIER_FACTOR: f64 = 2.0;

/// cfg.color 게이트를 거쳐 색상을 적용한다. 비활성 시 원문 그대로.
/// (text.rs의 paint와 같은 톤.)
fn paint(s: &str, enabled: bool, f: impl FnOnce(&str) -> ColoredString) -> String {
    if enabled {
        f(s).to_string()
    } else {
        s.to_string()
    }
}

/// 호스트의 모든 IP를 개별 연결로 프로브하고 IP별 표를 출력한다 (이상치 플래그).
pub async fn run_fanout(cfg: &ProbeConfig, color: bool) -> anyhow::Result<ExitCode> {
    let host = cfg
        .url
        .host_str()
        .context("target URL has no host for fanout")?
        .to_string();
    let port = cfg
        .url
        .port_or_known_default()
        .context("target URL has no port for fanout")?;

    // cfg.resolve가 이미 지정돼 있으면 그 IP 하나만 대상으로 한다.
    // 아니면 호스트:포트를 해석해 ip_family 필터 후 전부 모은다.
    let ips: Vec<IpAddr> = if let Some(ip) = cfg.resolve {
        vec![ip]
    } else {
        resolve_all(&host, port, cfg.ip_family).await?
    };
    if ips.is_empty() {
        anyhow::bail!("no addresses resolved for {host}:{port}");
    }

    println!("fanout {host}:{port} — {} address(es)", ips.len());

    // 각 IP를 개별 연결로 순차 프로브한다 (resolve override 트릭).
    let mut rows: Vec<Row> = Vec::with_capacity(ips.len());
    for (seq, ip) in ips.iter().enumerate() {
        let mut c = cfg.clone();
        c.resolve = Some(*ip);
        c.ip_family = IpFamily::Auto; // resolve가 우선이므로 패밀리는 무관.
        let result = crate::probe::probe(&c, seq as u64).await;
        rows.push(Row::from_result(*ip, &result));
    }

    // IP 정렬 순서로 안정화.
    rows.sort_by_key(|a| a.ip);

    // 이상치 판정: status가 다수와 다르거나 total이 중앙값의 OUTLIER_FACTOR 이상.
    let median = median_total(&rows);
    let majority = majority_status(&rows);
    for row in &mut rows {
        row.outlier = row.is_outlier(median, majority);
    }

    print_fanout_table(&rows, color);

    let any_fail = rows.iter().any(|r| !r.ok);
    let any_outlier = rows.iter().any(|r| r.outlier);
    if any_fail || any_outlier {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// IPv4 강제와 IPv6 강제를 각각 1회 프로브해 단계별로 나란히 비교한다.
pub async fn run_all_families(cfg: &ProbeConfig, color: bool) -> anyhow::Result<ExitCode> {
    let host = cfg
        .url
        .host_str()
        .context("target URL has no host for family comparison")?
        .to_string();
    let port = cfg
        .url
        .port_or_known_default()
        .context("target URL has no port for family comparison")?;

    println!("families {host}:{port} — IPv4 vs IPv6");

    // 각 패밀리에 대해 해석 가능 여부를 먼저 확인한 뒤 1회 프로브한다.
    // resolve는 None으로 두고 ip_family로 강제해 probe가 직접 필터/연결하게 한다.
    let v4 = probe_family(cfg, &host, port, IpFamily::V4).await;
    let v6 = probe_family(cfg, &host, port, IpFamily::V6).await;

    print_family_compare(&v4, &v6, color);

    // 종료 코드: 둘 다 성공이면 SUCCESS, 한쪽이라도 실패/해석불가면 1.
    let ok = v4.is_ok_success() && v6.is_ok_success();
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

// ---------------------------------------------------------------------------
// per-IP fanout
// ---------------------------------------------------------------------------

/// 호스트:포트를 해석해 ip_family로 필터링한 모든 IP를 순서 보존·중복 제거로 모은다.
async fn resolve_all(host: &str, port: u16, family: IpFamily) -> anyhow::Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .with_context(|| format!("DNS lookup for {host}:{port} failed"))?;

    let mut ips: Vec<IpAddr> = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if family_matches(ip, family) && !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

fn family_matches(ip: IpAddr, family: IpFamily) -> bool {
    match family {
        IpFamily::Auto => true,
        IpFamily::V4 => ip.is_ipv4(),
        IpFamily::V6 => ip.is_ipv6(),
    }
}

/// 표 한 행 — 한 IP의 프로브 요약.
struct Row {
    ip: IpAddr,
    /// 네트워크 성공 여부.
    ok: bool,
    /// 성공 시 HTTP 상태 코드.
    status: Option<u16>,
    /// 실패 시 실패 단계 라벨 (예: "tcp", "tls").
    fail_phase: Option<String>,
    /// 합산 ttfb (ms). 실패 시 None일 수 있다.
    ttfb_ms: Option<f64>,
    /// 합산 total (ms). 측정된 hop이 없으면 None.
    total_ms: Option<f64>,
    /// 최종 hop의 TLS 버전 (없으면 None).
    tls_version: Option<String>,
    /// 이상치 플래그 (판정 후 채워짐).
    outlier: bool,
}

impl Row {
    fn from_result(ip: IpAddr, result: &ProbeResult) -> Self {
        let summed = result.summed_timings();
        let has_hop = result.final_hop().is_some();
        let tls_version = result
            .final_hop()
            .and_then(|h| h.tls.as_ref())
            .map(|t| t.version.clone());
        Row {
            ip,
            ok: result.is_success(),
            status: result.status(),
            fail_phase: result.error.as_ref().map(|e| e.phase.to_string()),
            // hop이 하나도 없으면(예: DNS/Setup 실패) 시간 값은 의미가 없으므로 None.
            ttfb_ms: has_hop.then_some(summed.ttfb_ms),
            total_ms: has_hop.then_some(summed.total_ms),
            tls_version,
            outlier: false,
        }
    }

    /// status 셀에 들어갈 텍스트 (성공=상태코드, 실패=ERROR(phase)).
    fn status_text(&self) -> String {
        match (self.status, &self.fail_phase) {
            (Some(code), _) => code.to_string(),
            (None, Some(phase)) => format!("ERR:{phase}"),
            (None, None) => "ERR".to_string(),
        }
    }

    /// 이 행이 이상치인지 판정한다.
    /// - 네트워크 실패면 이상치.
    /// - 다수 status가 존재하는데 이 행의 status가 다르면 이상치.
    /// - total이 중앙값의 OUTLIER_FACTOR 이상이면 이상치.
    fn is_outlier(&self, median: Option<f64>, majority: Option<u16>) -> bool {
        if !self.ok {
            return true;
        }
        if let (Some(maj), Some(st)) = (majority, self.status)
            && st != maj
        {
            return true;
        }
        if let (Some(med), Some(total)) = (median, self.total_ms)
            && med > 0.0
            && total >= med * OUTLIER_FACTOR
        {
            return true;
        }
        false
    }
}

/// 성공 행들의 total 중앙값 (성공 행이 없으면 None).
fn median_total(rows: &[Row]) -> Option<f64> {
    let mut totals: Vec<f64> = rows
        .iter()
        .filter(|r| r.ok)
        .filter_map(|r| r.total_ms)
        .collect();
    if totals.is_empty() {
        return None;
    }
    totals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = totals.len();
    if n % 2 == 1 {
        Some(totals[n / 2])
    } else {
        Some((totals[n / 2 - 1] + totals[n / 2]) / 2.0)
    }
}

/// 성공 행들 중 최빈 status. 동률이거나 성공 행이 없으면 None
/// (None이면 status 기준 이상치 판정을 하지 않는다).
fn majority_status(rows: &[Row]) -> Option<u16> {
    let mut counts: Vec<(u16, usize)> = Vec::new();
    for r in rows.iter().filter(|r| r.ok) {
        if let Some(st) = r.status {
            if let Some(entry) = counts.iter_mut().find(|(c, _)| *c == st) {
                entry.1 += 1;
            } else {
                counts.push((st, 1));
            }
        }
    }
    let max = counts.iter().map(|(_, n)| *n).max()?;
    let top: Vec<u16> = counts
        .iter()
        .filter(|(_, n)| *n == max)
        .map(|(c, _)| *c)
        .collect();
    // 단일 최빈값일 때만 다수로 인정 (동률이면 어느 쪽도 이상치로 보지 않음).
    if top.len() == 1 { Some(top[0]) } else { None }
}

/// IP별 정렬 표를 출력한다.
fn print_fanout_table(rows: &[Row], color: bool) {
    // IP 컬럼 폭은 가장 긴 IP 문자열에 맞춘다 (IPv6 대비).
    let ip_w = rows
        .iter()
        .map(|r| r.ip.to_string().len())
        .max()
        .unwrap_or(15)
        .max("IP".len());

    println!(
        "{:<ip_w$}  {:>7}  {:>9}  {:>9}  TLS",
        "IP", "STATUS", "TTFB", "TOTAL"
    );

    for row in rows {
        let ip = format!("{:<ip_w$}", row.ip.to_string());
        let status = paint_status(&row.status_text(), row.status, row.ok, color);
        let ttfb = match row.ttfb_ms {
            Some(v) => format!("{v:>7.1}ms"),
            None => format!("{:>9}", "-"),
        };
        let total = match row.total_ms {
            Some(v) => format!("{v:>7.1}ms"),
            None => format!("{:>9}", "-"),
        };
        let tls = row.tls_version.as_deref().unwrap_or("-");
        let mark = outlier_mark(row.outlier, color);
        println!("{ip}  {status:>7}  {ttfb}  {total}  {tls}{mark}");
    }
}

/// status 셀 색칠: 2xx 초록 / 3xx 노랑 / 그 외·실패 빨강.
fn paint_status(text: &str, status: Option<u16>, ok: bool, color: bool) -> String {
    if !ok {
        return paint(text, color, |s| s.red().bold());
    }
    match status {
        Some(200..=299) => paint(text, color, |s| s.green().bold()),
        Some(300..=399) => paint(text, color, |s| s.yellow()),
        Some(_) => paint(text, color, |s| s.red().bold()),
        None => text.to_string(),
    }
}

/// 이상치 마크 — color면 노랑 강조, 비-color면 텍스트만.
fn outlier_mark(outlier: bool, color: bool) -> String {
    if !outlier {
        return String::new();
    }
    let mark = if color { "  ⚠ outlier" } else { "  outlier" };
    paint(mark, color, |s| s.yellow())
}

// ---------------------------------------------------------------------------
// v4/v6 divergence
// ---------------------------------------------------------------------------

/// 한 패밀리의 비교 결과: 해석 불가 / 프로브 실패 / 성공.
enum FamilyOutcome {
    /// 해당 패밀리 레코드가 없어 프로브 자체를 못 했다.
    Unresolved(String),
    /// 프로브를 수행했다 (성공/실패는 ProbeResult.error로 구분).
    Probed(Box<ProbeResult>),
}

impl FamilyOutcome {
    /// 네트워크 성공으로 끝났는지 (해석 불가/실패면 false).
    fn is_ok_success(&self) -> bool {
        match self {
            FamilyOutcome::Unresolved(_) => false,
            FamilyOutcome::Probed(r) => r.is_success(),
        }
    }
}

/// 한 패밀리로 강제해 1회 프로브한다. 먼저 해석 가능 여부를 확인한다.
async fn probe_family(cfg: &ProbeConfig, host: &str, port: u16, family: IpFamily) -> FamilyOutcome {
    // 해당 패밀리 주소가 있는지 먼저 확인 — 없으면 "한쪽만 표시"를 위해 명시한다.
    let ips = match resolve_all(host, port, family).await {
        Ok(ips) => ips,
        Err(e) => return FamilyOutcome::Unresolved(format!("DNS lookup failed: {e}")),
    };
    if ips.is_empty() {
        return FamilyOutcome::Unresolved(format!("no {} address records", family_label(family)));
    }

    let mut c = cfg.clone();
    c.resolve = None; // 패밀리 강제만 사용 (probe가 직접 필터/선택).
    c.ip_family = family;
    let result = crate::probe::probe(&c, 0).await;
    FamilyOutcome::Probed(Box::new(result))
}

fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::V4 => "IPv4",
        IpFamily::V6 => "IPv6",
        IpFamily::Auto => "IP",
    }
}

/// IPv4 vs IPv6 단계별 비교를 출력한다.
fn print_family_compare(v4: &FamilyOutcome, v6: &FamilyOutcome, color: bool) {
    // 헤더 줄: 각 패밀리의 연결 IP/상태 또는 해석 불가/실패 사유.
    print_family_header("IPv4", v4, color);
    print_family_header("IPv6", v6, color);
    println!();

    let t4 = outcome_timings(v4);
    let t6 = outcome_timings(v6);

    // 둘 다 시간 측정이 없으면 단계 표는 생략한다.
    if t4.is_none() && t6.is_none() {
        return;
    }

    println!("{:<10}  {:>11}  {:>11}  DELTA", "PHASE", "IPv4", "IPv6");
    // dns/tcp/tls/ttfb/download/total을 나란히.
    for phase in PHASES {
        let a = t4.and_then(|t| (phase.get)(&t));
        let b = t6.and_then(|t| (phase.get)(&t));
        // 한쪽이라도 값이 있는 단계만 출력 (둘 다 None인 단계 — 예: http의 tls — 생략).
        if a.is_none() && b.is_none() {
            continue;
        }
        let a_cell = fmt_ms_cell(a);
        let b_cell = fmt_ms_cell(b);
        let delta = delta_cell(a, b, color);
        println!("{:<10}  {a_cell:>11}  {b_cell:>11}  {delta}", phase.name);
    }
}

/// 한 패밀리의 헤더 한 줄 (연결 IP + 상태, 또는 사유).
fn print_family_header(label: &str, outcome: &FamilyOutcome, color: bool) {
    match outcome {
        FamilyOutcome::Unresolved(reason) => {
            let body = paint(&format!("{label}: {reason}"), color, |s| s.yellow());
            println!("{body}");
        }
        FamilyOutcome::Probed(r) => {
            if let Some(err) = &r.error {
                let body = paint(
                    &format!("{label}: ERROR({}) {}", err.phase, err.message),
                    color,
                    |s| s.red().bold(),
                );
                println!("{body}");
            } else {
                let ip = r
                    .final_hop()
                    .map(|h| h.ip.to_string())
                    .unwrap_or_else(|| "?".to_string());
                let status = r.status().map(|s| s.to_string()).unwrap_or_default();
                let status = paint_status(&status, r.status(), true, color);
                let tls = r
                    .final_hop()
                    .and_then(|h| h.tls.as_ref())
                    .map(|t| format!(" {}", t.version))
                    .unwrap_or_default();
                println!("{label}: {ip} {status}{tls}");
            }
        }
    }
}

/// 성공 프로브의 합산 타이밍 (실패/해석불가면 None).
fn outcome_timings(outcome: &FamilyOutcome) -> Option<PhaseTimings> {
    match outcome {
        FamilyOutcome::Probed(r) if r.is_success() => Some(r.summed_timings()),
        _ => None,
    }
}

/// 단계 한 개의 이름 + PhaseTimings에서 값을 꺼내는 접근자.
struct PhaseRow {
    name: &'static str,
    get: fn(&PhaseTimings) -> Option<f64>,
}

/// 비교 표에 출력할 단계 순서.
const PHASES: &[PhaseRow] = &[
    PhaseRow {
        name: "dns",
        get: |t| t.dns_ms,
    },
    PhaseRow {
        name: "tcp",
        get: |t| Some(t.tcp_ms),
    },
    PhaseRow {
        name: "tls",
        get: |t| t.tls_ms,
    },
    PhaseRow {
        name: "ttfb",
        get: |t| Some(t.ttfb_ms),
    },
    PhaseRow {
        name: "download",
        get: |t| Some(t.download_ms),
    },
    PhaseRow {
        name: "total",
        get: |t| Some(t.total_ms),
    },
];

/// ms 셀 포맷 ("-"는 값 없음).
fn fmt_ms_cell(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{v:.1}ms"),
        None => "-".to_string(),
    }
}

/// v4 - v6 차이 셀. 한쪽만 있으면 "-". |delta|가 둘 중 작은 값의 일정 비율 이상이면
/// (또는 절대값이 큰 경우) color로 강조한다.
fn delta_cell(a: Option<f64>, b: Option<f64>, color: bool) -> String {
    let (Some(a), Some(b)) = (a, b) else {
        return "-".to_string();
    };
    let diff = a - b;
    let text = format!("{diff:+.1}ms");
    // 유의미한 차이 판정: 더 작은 쪽 대비 50% 이상 벌어지면 강조.
    let smaller = a.min(b).max(0.0);
    let significant = diff.abs() >= (smaller * 0.5).max(1.0) && diff.abs() >= 5.0;
    if significant {
        paint(&text, color, |s| s.yellow())
    } else {
        text
    }
}

// ---------------------------------------------------------------------------
// 테스트
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn row(ip: u8, ok: bool, status: Option<u16>, total: Option<f64>) -> Row {
        Row {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)),
            ok,
            status,
            fail_phase: if ok { None } else { Some("tcp".to_string()) },
            ttfb_ms: total,
            total_ms: total,
            tls_version: None,
            outlier: false,
        }
    }

    #[test]
    fn median_odd_and_even() {
        let odd = vec![
            row(1, true, Some(200), Some(10.0)),
            row(2, true, Some(200), Some(30.0)),
            row(3, true, Some(200), Some(20.0)),
        ];
        assert_eq!(median_total(&odd), Some(20.0));

        let even = vec![
            row(1, true, Some(200), Some(10.0)),
            row(2, true, Some(200), Some(20.0)),
            row(3, true, Some(200), Some(30.0)),
            row(4, true, Some(200), Some(40.0)),
        ];
        assert_eq!(median_total(&even), Some(25.0));
    }

    #[test]
    fn median_ignores_failed_and_empty() {
        let rows = vec![
            row(1, true, Some(200), Some(10.0)),
            row(2, false, None, None),
        ];
        assert_eq!(median_total(&rows), Some(10.0));
        // 성공 행이 없으면 None.
        let none = vec![row(1, false, None, None)];
        assert_eq!(median_total(&none), None);
    }

    #[test]
    fn majority_single_winner() {
        let rows = vec![
            row(1, true, Some(200), Some(10.0)),
            row(2, true, Some(200), Some(11.0)),
            row(3, true, Some(503), Some(12.0)),
        ];
        assert_eq!(majority_status(&rows), Some(200));
    }

    #[test]
    fn majority_tie_is_none() {
        // 동률(200 vs 500)이면 어느 쪽도 다수가 아니다 → None.
        let rows = vec![
            row(1, true, Some(200), Some(10.0)),
            row(2, true, Some(500), Some(11.0)),
        ];
        assert_eq!(majority_status(&rows), None);
    }

    #[test]
    fn outlier_failed_row() {
        let r = row(9, false, None, None);
        assert!(r.is_outlier(Some(10.0), Some(200)));
    }

    #[test]
    fn outlier_status_mismatch() {
        // 다수가 200인데 503이면 이상치.
        let r = row(9, true, Some(503), Some(10.0));
        assert!(r.is_outlier(Some(10.0), Some(200)));
        // 다수와 같은 status + 정상 latency면 이상치 아님.
        let ok = row(8, true, Some(200), Some(10.0));
        assert!(!ok.is_outlier(Some(10.0), Some(200)));
    }

    #[test]
    fn outlier_latency_factor() {
        // 중앙값 10ms, total 25ms (2.5x) → 이상치.
        let slow = row(9, true, Some(200), Some(25.0));
        assert!(slow.is_outlier(Some(10.0), Some(200)));
        // 정확히 2x 경계 → 이상치 (>=).
        let edge = row(8, true, Some(200), Some(20.0));
        assert!(edge.is_outlier(Some(10.0), Some(200)));
        // 1.9x → 이상치 아님.
        let fine = row(7, true, Some(200), Some(19.0));
        assert!(!fine.is_outlier(Some(10.0), Some(200)));
    }

    #[test]
    fn family_filter() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(family_matches(v4, IpFamily::V4));
        assert!(!family_matches(v4, IpFamily::V6));
        assert!(family_matches(v6, IpFamily::V6));
        assert!(!family_matches(v6, IpFamily::V4));
        assert!(family_matches(v4, IpFamily::Auto));
        assert!(family_matches(v6, IpFamily::Auto));
    }

    #[test]
    fn status_text_variants() {
        assert_eq!(row(1, true, Some(200), Some(1.0)).status_text(), "200");
        assert_eq!(row(2, false, None, None).status_text(), "ERR:tcp");
    }
}
