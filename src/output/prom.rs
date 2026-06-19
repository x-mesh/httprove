//! Prometheus/OpenMetrics 텍스트 포맷 렌더링.
//!
//! `--prom`(요약 대신 출력, node_exporter textfile collector용)과
//! `--listen`(exporter의 /metrics)이 공용으로 사용한다.
//!
//! ## 메트릭 (fleet/targets_* 외에는 모두 target 레이블 포함)
//! - `httprove_probes_total{target}` counter — sent
//! - `httprove_probe_failures_total{target}` counter — failed (네트워크 실패)
//! - `httprove_expect_failures_total{target}` counter — expect_failed
//! - `httprove_phase_milliseconds{target,phase,stat}` gauge —
//!   phase ∈ dns|tcp|tls|ttfb|download|total, stat ∈ min|mean|stddev|p50|p95|p99|max
//!   (샘플 없는 단계는 생략)
//! - `httprove_status_total{target,code}` counter — 상태 코드 분포
//! - `httprove_last_total_milliseconds{target}` gauge — 마지막 성공 프로브 total
//! - `httprove_last_body_bytes{target}` gauge — 마지막 성공 프로브 바디 크기(전체 hop 합)
//! - `httprove_cert_expiry_days{target}` gauge — 마지막 관측 leaf 인증서 잔여 일수
//! - `httprove_cert_chain_depth{target}` gauge — 마지막 체인의 cert 수(서버 전송, leaf 먼저)
//! - `httprove_cert_chain_incomplete{target}` gauge — 중간 인증서 누락 추정(1/0)
//! - `httprove_cert_weakest_expiry_days{target}` gauge — 체인 최약 링크 잔여 일수(음수=만료)
//! - `httprove_tls_info{target,version,cipher,kx_group,alpn}` gauge — 협상된 TLS 파라미터(값 1)
//! - `httprove_server_timing_milliseconds{target,metric}` gauge — 서버 Server-Timing 분해(ms)
//! - `httprove_throughput_bytes_per_second{target,stat}` gauge — goodput 분포(합산 바디>=4096)
//! - `httprove_hops_total{target}` counter — 성공 프로브 전체 hop 수
//! - `httprove_connection_reused_total{target}` counter — keep-alive 재사용 hop 수
//! - `httprove_connection_reuse_ratio{target}` gauge — 재사용 hop 비율(0-1)
//! - `httprove_http_version_total{target,version}` counter — hop별 HTTP 버전 분포
//! - `httprove_dns_answer_changed_total{target}` counter — resolved IP 집합 변경 횟수
//! - `httprove_dns_resolved_ip_count{target}` gauge — 마지막 성공 resolved IP 수(final hop)
//! - `httprove_verdict_state{target,state}` gauge — 최신 판정(pass/degraded/down, 현재=1)
//! - `httprove_fleet_phase_milliseconds{phase,stat,agg}` gauge — 전 타깃 단계 rollup(worst/best)
//! - `httprove_target_up{target}` gauge — 타깃 health(1=up/degraded, 0=down)
//! - `httprove_targets_total` gauge — 모니터링 타깃 수(target 레이블 없음)
//! - `httprove_targets_down` gauge — 최신 DOWN 판정 타깃 수(target 레이블 없음)
//!
//! ## 규칙
//! - 각 메트릭 이름마다 # HELP / # TYPE 헤더를 1회 출력.
//! - 레이블 값 이스케이프: `\` → `\\`, `"` → `\"`, 개행 → `\n`.
//! - counter 메트릭은 누적값 그대로 (StatsCollector가 단조 증가).
//! - 마지막 줄 끝에 개행 포함.

use crate::stats::{Phase, PhaseStats, StatsCollector};
use crate::types::{ProbeResult, VerdictState};

/// 한 타깃의 메트릭 입력.
pub struct TargetMetrics<'a> {
    /// 타깃 URL 문자열 (target 레이블 값).
    pub target: &'a str,
    pub stats: &'a StatsCollector,
    /// 마지막 성공 ProbeResult (last_* 및 cert 메트릭용, 없으면 해당 메트릭 생략).
    pub last_success: Option<&'a ProbeResult>,
    /// 최신 결과(error 포함)의 health 판정. 호출처에서 `verdict::assess(latest).state`로
    /// precompute한다 — last_success가 아니라 *최신* 결과여야 실패를 Down으로 반영한다.
    /// None이면 아직 결과 없는 warmup → verdict/up/down 메트릭에서 not-down으로 취급.
    pub verdict_state: Option<VerdictState>,
}

/// phase 게이지의 stat 레이블 출력 순서.
const STAT_ORDER: [&str; 7] = ["min", "mean", "stddev", "p50", "p95", "p99", "max"];

/// Prometheus 레이블 값 이스케이프: `\` → `\\`, `"` → `\"`, 개행 → `\n`.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// VerdictState를 메트릭 state 레이블 슬러그로 변환한다. B13.
fn verdict_label(s: VerdictState) -> &'static str {
    match s {
        VerdictState::Pass => "pass",
        VerdictState::Degraded => "degraded",
        VerdictState::Down => "down",
    }
}

/// 메트릭 1개 분량(HELP/TYPE 헤더 + 샘플 라인들)을 out에 추가한다.
/// 샘플 라인이 하나도 없으면 헤더 포함 전체를 생략한다.
fn push_section(out: &mut String, name: &str, help: &str, kind: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
}

/// 전체 타깃의 메트릭을 OpenMetrics 텍스트로 렌더링한다.
///
/// 출력 순서는 결정적이다: 메트릭 이름 순서(아래 고정) → 주어진 타깃 순서
/// → (phase 메트릭은) Phase::ALL 순서 → stat 순서, (status는) 코드 오름차순.
pub fn render(targets: &[TargetMetrics<'_>]) -> String {
    let mut out = String::new();

    // --- counter 3종: 타깃마다 1줄 (0이어도 출력 — 단조 증가 시작점) -----------
    let probes: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "httprove_probes_total{{target=\"{}\"}} {}",
                escape_label(t.target),
                t.stats.sent()
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_probes_total",
        "Total probes sent.",
        "counter",
        &probes,
    );

    let failures: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "httprove_probe_failures_total{{target=\"{}\"}} {}",
                escape_label(t.target),
                t.stats.failed()
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_probe_failures_total",
        "Total probes that failed at the network level.",
        "counter",
        &failures,
    );

    let expect_failures: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "httprove_expect_failures_total{{target=\"{}\"}} {}",
                escape_label(t.target),
                t.stats.expect_failed()
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_expect_failures_total",
        "Total probes that succeeded but violated --expect assertions.",
        "counter",
        &expect_failures,
    );

    // --- 단계별 시간 게이지: 샘플 없는 단계는 생략 ---------------------------
    let mut phase_lines = Vec::new();
    for t in targets {
        let target = escape_label(t.target);
        for phase in Phase::ALL {
            let Some(s) = t.stats.phase_stats(phase) else {
                continue;
            };
            let values = [s.min, s.mean, s.stddev, s.p50, s.p95, s.p99, s.max];
            for (stat, value) in STAT_ORDER.iter().zip(values) {
                phase_lines.push(format!(
                    "httprove_phase_milliseconds{{target=\"{target}\",phase=\"{}\",stat=\"{stat}\"}} {value}",
                    phase.label()
                ));
            }
        }
    }
    push_section(
        &mut out,
        "httprove_phase_milliseconds",
        "Per-phase timing statistics in milliseconds (summed over redirect hops).",
        "gauge",
        &phase_lines,
    );

    // --- B7 goodput(bytes/s) 분포: 임계 통과 성공 프로브가 없으면 섹션 생략 ----------
    let mut throughput_lines = Vec::new();
    for t in targets {
        let Some(s) = t.stats.throughput_stats() else {
            continue;
        };
        let target = escape_label(t.target);
        let values = [s.min, s.mean, s.stddev, s.p50, s.p95, s.p99, s.max];
        for (stat, value) in STAT_ORDER.iter().zip(values) {
            throughput_lines.push(format!(
                "httprove_throughput_bytes_per_second{{target=\"{target}\",stat=\"{stat}\"}} {value}"
            ));
        }
    }
    push_section(
        &mut out,
        "httprove_throughput_bytes_per_second",
        "Download goodput in bytes/s (sum of hop body_bytes / sum of hop download_seconds) for successful probes whose total body >= 4096 bytes.",
        "gauge",
        &throughput_lines,
    );

    // --- 상태 코드 분포: BTreeMap이라 코드 오름차순 ---------------------------
    let mut status_lines = Vec::new();
    for t in targets {
        let target = escape_label(t.target);
        for (code, count) in t.stats.status_counts() {
            status_lines.push(format!(
                "httprove_status_total{{target=\"{target}\",code=\"{code}\"}} {count}"
            ));
        }
    }
    push_section(
        &mut out,
        "httprove_status_total",
        "Final-hop HTTP status code distribution.",
        "counter",
        &status_lines,
    );

    // --- B9 연결 재사용/HTTP 버전: counter는 0이어도 출력(단조 증가 시작점) ----------
    let hops_total_lines: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "httprove_hops_total{{target=\"{}\"}} {}",
                escape_label(t.target),
                t.stats.hops_total()
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_hops_total",
        "Total request hops observed across successful probes.",
        "counter",
        &hops_total_lines,
    );

    let reused_lines: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "httprove_connection_reused_total{{target=\"{}\"}} {}",
                escape_label(t.target),
                t.stats.hops_reused()
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_connection_reused_total",
        "Total request hops that reused an existing keep-alive connection.",
        "counter",
        &reused_lines,
    );

    // reuse ratio 게이지: hop이 하나도 없으면(0/0 회피) 라인을 만들지 않는다.
    let mut reuse_ratio_lines = Vec::new();
    for t in targets {
        let total = t.stats.hops_total();
        if total == 0 {
            continue;
        }
        let ratio = t.stats.hops_reused() as f64 / total as f64;
        reuse_ratio_lines.push(format!(
            "httprove_connection_reuse_ratio{{target=\"{}\"}} {ratio}",
            escape_label(t.target)
        ));
    }
    push_section(
        &mut out,
        "httprove_connection_reuse_ratio",
        "Fraction of probe hops that reused a keep-alive connection (0-1).",
        "gauge",
        &reuse_ratio_lines,
    );

    // HTTP 버전 분포: BTreeMap이라 버전 슬러그 오름차순. 샘플 없으면 섹션 생략.
    let mut version_lines = Vec::new();
    for t in targets {
        let target = escape_label(t.target);
        for (version, count) in t.stats.http_version_counts() {
            version_lines.push(format!(
                "httprove_http_version_total{{target=\"{target}\",version=\"{}\"}} {count}",
                escape_label(version)
            ));
        }
    }
    push_section(
        &mut out,
        "httprove_http_version_total",
        "Per-hop HTTP version distribution across successful probes.",
        "counter",
        &version_lines,
    );

    // --- 마지막 성공 프로브 기반 게이지: 성공이 없으면 생략 -------------------
    let mut last_total_lines = Vec::new();
    let mut last_body_lines = Vec::new();
    let mut cert_lines = Vec::new();
    // v0.3 추가 메트릭(전부 마지막 성공 스냅샷): 전체 체인 진단(B6), 협상 TLS(B5),
    // 서버측 Server-Timing 분해(B14). 모두 last_success가 없으면 라인을 안 만들고
    // push_section이 빈 섹션을 헤더째 생략한다.
    let mut chain_depth_lines = Vec::new();
    let mut chain_incomplete_lines = Vec::new();
    let mut weakest_expiry_lines = Vec::new();
    let mut tls_info_lines = Vec::new();
    let mut server_timing_lines = Vec::new();
    for t in targets {
        let Some(last) = t.last_success else {
            continue;
        };
        let target = escape_label(t.target);
        last_total_lines.push(format!(
            "httprove_last_total_milliseconds{{target=\"{target}\"}} {}",
            last.total_ms
        ));
        let body_bytes: u64 = last.hops.iter().map(|h| h.body_bytes).sum();
        last_body_lines.push(format!(
            "httprove_last_body_bytes{{target=\"{target}\"}} {body_bytes}"
        ));
        // leaf 인증서가 없는 대상(http)은 cert 메트릭 생략.
        if let Some(cert) = last.leaf_cert() {
            cert_lines.push(format!(
                "httprove_cert_expiry_days{{target=\"{target}\"}} {}",
                cert.days_remaining
            ));
        }

        // B6: 전체 체인 깊이/완결성/최약 링크 만료. leaf_cert()는 leaf 1장뿐이라
        // depth/weakest엔 부족하므로, cert를 실제 받은 최종 https hop의 전체 cert_chain을
        // 동기 분석한다(chain::analyze는 순수·무네트워크·패닉 없음 — 빈 체인은 default).
        if let Some(hop) = last.hops.iter().rev().find(|h| !h.cert_chain.is_empty()) {
            let analysis = crate::chain::analyze(&hop.cert_chain);
            chain_depth_lines.push(format!(
                "httprove_cert_chain_depth{{target=\"{target}\"}} {}",
                hop.cert_chain.len()
            ));
            chain_incomplete_lines.push(format!(
                "httprove_cert_chain_incomplete{{target=\"{target}\"}} {}",
                if analysis.incomplete { 1 } else { 0 }
            ));
            weakest_expiry_lines.push(format!(
                "httprove_cert_weakest_expiry_days{{target=\"{target}\"}} {}",
                analysis.weakest_days
            ));
        }

        // B5: 협상된 TLS 파라미터를 info-gauge로(값은 항상 1). http/실패 대상은 tls가
        // None이라 생략. alpn/kx_group은 Option — 없으면 빈 문자열 레이블로 둔다(시리즈
        // 식별 안정성을 위해 레이블 자체는 항상 같은 집합을 유지).
        if let Some(tls) = last.final_hop().and_then(|h| h.tls.as_ref()) {
            let version = escape_label(&tls.version);
            let cipher = escape_label(&tls.cipher);
            let kx_group = escape_label(tls.kx_group.as_deref().unwrap_or(""));
            let alpn = escape_label(tls.alpn.as_deref().unwrap_or(""));
            tls_info_lines.push(format!(
                "httprove_tls_info{{target=\"{target}\",version=\"{version}\",cipher=\"{cipher}\",kx_group=\"{kx_group}\",alpn=\"{alpn}\"}} 1"
            ));
        }

        // B14: 서버가 보고한 Server-Timing(예: db;dur=120, cache;dur=8)을 단계별 ms로 노출.
        // 같은 metric 이름의 중복은 last-wins, 출력은 이름 오름차순(결정성)으로 BTreeMap에 모은다.
        // dur이 없거나 비유한/음수인 엔트리는 라인을 만들지 않는다(잘못된 게이지 값 방지).
        if let Some(hop) = last.final_hop() {
            let mut timings: std::collections::BTreeMap<String, f64> =
                std::collections::BTreeMap::new();
            for (metric, dur) in crate::otlp::parse_server_timing(&hop.response_headers) {
                if let Some(ms) = dur
                    && ms.is_finite()
                    && ms >= 0.0
                {
                    timings.insert(metric, ms);
                }
            }
            for (metric, ms) in timings {
                let metric = escape_label(&metric);
                server_timing_lines.push(format!(
                    "httprove_server_timing_milliseconds{{target=\"{target}\",metric=\"{metric}\"}} {ms}"
                ));
            }
        }
    }
    push_section(
        &mut out,
        "httprove_last_total_milliseconds",
        "Total time of the last successful probe in milliseconds.",
        "gauge",
        &last_total_lines,
    );
    push_section(
        &mut out,
        "httprove_last_body_bytes",
        "Body bytes of the last successful probe (sum over all hops).",
        "gauge",
        &last_body_lines,
    );
    push_section(
        &mut out,
        "httprove_cert_expiry_days",
        "Days until the last observed leaf certificate expires.",
        "gauge",
        &cert_lines,
    );
    push_section(
        &mut out,
        "httprove_cert_chain_depth",
        "Number of certificates in the last observed TLS chain (server-sent, leaf first).",
        "gauge",
        &chain_depth_lines,
    );
    push_section(
        &mut out,
        "httprove_cert_chain_incomplete",
        "1 if the last observed chain is missing intermediate certificate(s) (server sent leaf only), else 0.",
        "gauge",
        &chain_incomplete_lines,
    );
    push_section(
        &mut out,
        "httprove_cert_weakest_expiry_days",
        "Days until the soonest-expiring certificate in the whole chain expires (weakest link; negative if expired).",
        "gauge",
        &weakest_expiry_lines,
    );
    push_section(
        &mut out,
        "httprove_tls_info",
        "Negotiated TLS parameters of the last successful probe (value is always 1).",
        "gauge",
        &tls_info_lines,
    );
    push_section(
        &mut out,
        "httprove_server_timing_milliseconds",
        "Server-Timing durations reported by the server on the last successful probe, in milliseconds.",
        "gauge",
        &server_timing_lines,
    );

    // --- B11 DNS: answer-changed counter(stats 누적, 0 포함 전 타깃) + resolved IP 수 게이지 ---
    let dns_changed: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "httprove_dns_answer_changed_total{{target=\"{}\"}} {}",
                escape_label(t.target),
                t.stats.dns_answer_changes()
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_dns_answer_changed_total",
        "Total number of times the resolved IP set changed between consecutive successful probes.",
        "counter",
        &dns_changed,
    );

    // resolved IP 수 게이지: 마지막 성공의 최종 hop 기준. 성공이 없으면 섹션 생략.
    let mut dns_count_lines = Vec::new();
    for t in targets {
        let Some(last) = t.last_success else {
            continue;
        };
        let Some(hop) = last.final_hop() else {
            continue;
        };
        dns_count_lines.push(format!(
            "httprove_dns_resolved_ip_count{{target=\"{}\"}} {}",
            escape_label(t.target),
            hop.resolved_ips.len()
        ));
    }
    push_section(
        &mut out,
        "httprove_dns_resolved_ip_count",
        "Number of IP addresses returned by DNS for the last successful probe (final hop).",
        "gauge",
        &dns_count_lines,
    );

    // --- B13 verdict 상태: enum-gauge(현재 상태=1, 나머지=0). 노출 포맷이
    //     text/plain;version=0.0.4(Prometheus)라 OpenMetrics stateset TYPE는 무효 → gauge로.
    //     verdict_state None(warmup)이면 섹션 생략. ---
    let mut verdict_lines = Vec::new();
    for t in targets {
        let Some(state) = t.verdict_state else {
            continue;
        };
        let target = escape_label(t.target);
        for candidate in [
            VerdictState::Pass,
            VerdictState::Degraded,
            VerdictState::Down,
        ] {
            let v = if candidate == state { 1 } else { 0 };
            verdict_lines.push(format!(
                "httprove_verdict_state{{target=\"{target}\",state=\"{}\"}} {v}",
                verdict_label(candidate)
            ));
        }
    }
    push_section(
        &mut out,
        "httprove_verdict_state",
        "Current service-health verdict of the latest probe (1 for the active state, 0 otherwise).",
        "gauge",
        &verdict_lines,
    );

    // --- B12 fleet rollup: 전 타깃에 걸친 단계별 worst(max)/best(min) 집계. 어느 타깃도
    //     샘플이 없는 단계는 생략. fleet/targets_* 메트릭은 의도적으로 target 레이블이 없다
    //     (플릿 단위 스칼라/agg 축이라 target이 의미 없고 합성 행 충돌도 회피). ---
    let mut fleet_lines = Vec::new();
    for phase in Phase::ALL {
        let snaps: Vec<PhaseStats> = targets
            .iter()
            .filter_map(|t| t.stats.phase_stats(phase))
            .collect();
        if snaps.is_empty() {
            continue;
        }
        let pick = |s: &PhaseStats, stat: &str| -> f64 {
            match stat {
                "min" => s.min,
                "mean" => s.mean,
                "stddev" => s.stddev,
                "p50" => s.p50,
                "p95" => s.p95,
                "p99" => s.p99,
                _ => s.max,
            }
        };
        let p = phase.label();
        for stat in STAT_ORDER {
            let worst = snaps.iter().map(|s| pick(s, stat)).fold(f64::MIN, f64::max);
            let best = snaps.iter().map(|s| pick(s, stat)).fold(f64::MAX, f64::min);
            fleet_lines.push(format!(
                "httprove_fleet_phase_milliseconds{{phase=\"{p}\",stat=\"{stat}\",agg=\"worst\"}} {worst}"
            ));
            fleet_lines.push(format!(
                "httprove_fleet_phase_milliseconds{{phase=\"{p}\",stat=\"{stat}\",agg=\"best\"}} {best}"
            ));
        }
    }
    push_section(
        &mut out,
        "httprove_fleet_phase_milliseconds",
        "Fleet rollup of per-phase timing across all targets in milliseconds (agg=worst|best).",
        "gauge",
        &fleet_lines,
    );

    // --- B12 per-target up + fleet 스칼라(타깃이 없어도 0으로 항상 출력) -------------
    let up_lines: Vec<String> = targets
        .iter()
        .map(|t| {
            let up = if t.verdict_state == Some(VerdictState::Down) {
                0
            } else {
                1
            };
            format!(
                "httprove_target_up{{target=\"{}\"}} {up}",
                escape_label(t.target)
            )
        })
        .collect();
    push_section(
        &mut out,
        "httprove_target_up",
        "Per-target health from the latest probe (1=up/degraded, 0=down).",
        "gauge",
        &up_lines,
    );

    let total = targets.len();
    let down = targets
        .iter()
        .filter(|t| t.verdict_state == Some(VerdictState::Down))
        .count();
    push_section(
        &mut out,
        "httprove_targets_total",
        "Total number of monitored targets.",
        "gauge",
        &[format!("httprove_targets_total {total}")],
    );
    push_section(
        &mut out,
        "httprove_targets_down",
        "Number of monitored targets whose latest probe is judged DOWN.",
        "gauge",
        &[format!("httprove_targets_down {down}")],
    );

    out
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::types::{
        CertInfo, ErrorPhase, HopResult, PhaseTimings, ProbeError, ProbeResult, TlsInfo,
    };

    /// 성공 프로브 생성 헬퍼 (stats.rs 테스트와 동일 계열).
    fn ok_probe(target: &str, seq: u64, total: f64, with_dns_tls: bool, body: u64) -> ProbeResult {
        let timings = PhaseTimings {
            dns_ms: with_dns_tls.then_some(1.0),
            tcp_ms: 2.0,
            tls_ms: with_dns_tls.then_some(3.0),
            ttfb_ms: 4.0,
            download_ms: 5.0,
            total_ms: total,
        };
        ProbeResult {
            target: target.to_string(),
            seq,
            timestamp: Utc::now(),
            hops: vec![HopResult {
                url: target.to_string(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                reused_conn: false,
                local_addr: None,
                resolved_ips: vec![],
                http_version: "HTTP/1.1".to_string(),
                status: 200,
                timings,
                tls: None,
                cert_chain: vec![],
                response_headers: vec![],
                body_bytes: body,
                redirect_to: None,
            }],
            error: None,
            expect_failures: vec![],
            total_ms: total,
        }
    }

    /// 실패 프로브 생성 헬퍼.
    fn failed_probe(target: &str, seq: u64) -> ProbeResult {
        let mut p = ok_probe(target, seq, 999.0, true, 0);
        p.error = Some(ProbeError {
            phase: ErrorPhase::Tcp,
            message: "connection refused".to_string(),
            timed_out: false,
            hint: None,
        });
        p
    }

    /// 잔여 일수만 의미 있는 leaf 인증서 픽스처.
    fn leaf_cert(days_remaining: i64) -> CertInfo {
        CertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            san: vec!["example.com".to_string()],
            not_before: Utc::now(),
            not_after: Utc::now(),
            days_remaining,
            serial: "01".to_string(),
            sig_alg: "ECDSA-SHA256".to_string(),
            pubkey: "EC P-256".to_string(),
            is_ca: false,
            spki_sha256: String::new(),
            aia_ca_issuers: None,
        }
    }

    #[test]
    fn label_escaping() {
        assert_eq!(escape_label(r"back\slash"), r"back\\slash");
        assert_eq!(escape_label(r#"quo"te"#), r#"quo\"te"#);
        assert_eq!(escape_label("line\nbreak"), r"line\nbreak");
        assert_eq!(escape_label("plain ascii"), "plain ascii");
        // 복합 케이스.
        assert_eq!(escape_label("a\\\"\nb"), r#"a\\\"\nb"#);
    }

    #[test]
    fn render_escapes_target_label() {
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target: "https://ex\"am\\ple/",
            stats: &stats,
            last_success: None,
            verdict_state: None,
        }];
        let text = render(&tm);
        assert!(
            text.contains(r#"httprove_probes_total{target="https://ex\"am\\ple/"} 0"#),
            "got:\n{text}"
        );
    }

    #[test]
    fn render_known_counts() {
        let target = "https://example.com/";
        let mut stats = StatsCollector::new();

        // 성공 2건 (total 10, 20) + 네트워크 실패 1건.
        for r in [
            ok_probe(target, 0, 10.0, true, 100),
            ok_probe(target, 1, 20.0, true, 200),
            failed_probe(target, 2),
        ] {
            stats.record(&r);
        }
        // 어설션 위반 1건 (네트워크는 성공) — 인증서 포함, 마지막 성공이 된다.
        let mut bad = ok_probe(target, 3, 30.0, true, 300);
        bad.expect_failures
            .push("status 500 not in [200]".to_string());
        bad.hops[0].cert_chain = vec![leaf_cert(42)];
        stats.record(&bad);
        let last = Some(bad);

        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: last.as_ref(),
            verdict_state: None,
        }];
        let text = render(&tm);
        let t = r#"target="https://example.com/""#;

        // counter 3종.
        assert!(
            text.contains(&format!("httprove_probes_total{{{t}}} 4")),
            "got:\n{text}"
        );
        assert!(text.contains(&format!("httprove_probe_failures_total{{{t}}} 1")));
        assert!(text.contains(&format!("httprove_expect_failures_total{{{t}}} 1")));

        // 단계별 게이지: 성공 3건 → total min/max = 10/30, mean = 20.
        assert!(text.contains(&format!(
            "httprove_phase_milliseconds{{{t},phase=\"total\",stat=\"min\"}} 10"
        )));
        assert!(text.contains(&format!(
            "httprove_phase_milliseconds{{{t},phase=\"total\",stat=\"mean\"}} 20"
        )));
        assert!(text.contains(&format!(
            "httprove_phase_milliseconds{{{t},phase=\"total\",stat=\"max\"}} 30"
        )));
        // https 프로브였으므로 dns 단계도 존재.
        assert!(text.contains(&format!(
            "httprove_phase_milliseconds{{{t},phase=\"dns\",stat=\"p99\"}} 1"
        )));

        // 상태 코드 분포 / last_* / cert.
        assert!(text.contains(&format!("httprove_status_total{{{t},code=\"200\"}} 3")));
        assert!(text.contains(&format!("httprove_last_total_milliseconds{{{t}}} 30")));
        assert!(text.contains(&format!("httprove_last_body_bytes{{{t}}} 300")));
        assert!(text.contains(&format!("httprove_cert_expiry_days{{{t}}} 42")));

        // 마지막 줄 끝 개행.
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn header_once_and_targets_in_order() {
        let mut stats_a = StatsCollector::new();
        stats_a.record(&ok_probe("https://a.example/", 0, 10.0, false, 1));
        let mut stats_b = StatsCollector::new();
        stats_b.record(&ok_probe("https://b.example/", 0, 20.0, false, 2));

        let tm = [
            TargetMetrics {
                target: "https://a.example/",
                stats: &stats_a,
                last_success: None,
                verdict_state: None,
            },
            TargetMetrics {
                target: "https://b.example/",
                stats: &stats_b,
                last_success: None,
                verdict_state: None,
            },
        ];
        let text = render(&tm);

        // HELP/TYPE는 메트릭 이름마다 정확히 1회 (타깃 수와 무관).
        for name in [
            "httprove_probes_total",
            "httprove_probe_failures_total",
            "httprove_expect_failures_total",
            "httprove_phase_milliseconds",
            "httprove_status_total",
        ] {
            let help = format!("# HELP {name} ");
            let ty = format!("# TYPE {name} ");
            assert_eq!(text.matches(&help).count(), 1, "{name} HELP");
            assert_eq!(text.matches(&ty).count(), 1, "{name} TYPE");
        }

        // 메트릭 단위 그룹핑: a 라인 → b 라인 → 다음 메트릭 헤더 순.
        let a_line = text
            .find(r#"httprove_probes_total{target="https://a.example/"} 1"#)
            .expect("a probes line");
        let b_line = text
            .find(r#"httprove_probes_total{target="https://b.example/"} 1"#)
            .expect("b probes line");
        let next_header = text
            .find("# HELP httprove_probe_failures_total")
            .expect("failures header");
        assert!(a_line < b_line && b_line < next_header);
    }

    #[test]
    fn metrics_without_samples_are_omitted() {
        // 샘플이 전혀 없는 수집기: counter는 0으로 출력, 나머지는 헤더째 생략.
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target: "https://x.example/",
            stats: &stats,
            last_success: None,
            verdict_state: None,
        }];
        let text = render(&tm);

        assert!(text.contains(r#"httprove_probes_total{target="https://x.example/"} 0"#));
        assert!(text.contains(r#"httprove_probe_failures_total{target="https://x.example/"} 0"#));
        assert!(!text.contains("httprove_phase_milliseconds"));
        assert!(!text.contains("httprove_status_total"));
        assert!(!text.contains("httprove_last_total_milliseconds"));
        assert!(!text.contains("httprove_last_body_bytes"));
        assert!(!text.contains("httprove_cert_expiry_days"));
    }

    #[test]
    fn http_target_has_no_cert_metric() {
        // 인증서 체인이 없는 마지막 성공: last_*는 나오고 cert 메트릭만 생략.
        let target = "http://plain.example/";
        let mut stats = StatsCollector::new();
        let ok = ok_probe(target, 0, 12.0, false, 64);
        stats.record(&ok);

        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: Some(&ok),
            verdict_state: None,
        }];
        let text = render(&tm);

        assert!(
            text.contains(r#"httprove_last_total_milliseconds{target="http://plain.example/"} 12"#)
        );
        assert!(text.contains(r#"httprove_last_body_bytes{target="http://plain.example/"} 64"#));
        assert!(!text.contains("httprove_cert_expiry_days"));
        // http 대상: dns/tls 단계 샘플 없음 → 해당 라인 없음.
        assert!(!text.contains(r#"phase="dns""#));
        assert!(!text.contains(r#"phase="tls""#));
    }

    // === v0.3 PR-1: B6(cert chain) / B5(tls_info) / B14(server_timing) ===

    /// TLS 협상 픽스처.
    fn tls_info(alpn: Option<&str>, kx: Option<&str>) -> TlsInfo {
        TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher: "TLS13_AES_128_GCM_SHA256".to_string(),
            alpn: alpn.map(str::to_string),
            kx_group: kx.map(str::to_string),
        }
    }

    /// 마지막 성공 결과를 직접 조립해 render한 텍스트를 돌려준다.
    fn render_last(target: &str, mutate: impl FnOnce(&mut ProbeResult)) -> String {
        let mut p = ok_probe(target, 0, 10.0, true, 100);
        mutate(&mut p);
        let mut stats = StatsCollector::new();
        stats.record(&p);
        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: Some(&p),
            verdict_state: None,
        }];
        render(&tm)
    }

    #[test]
    fn b6_full_chain_depth_complete_weakest_min() {
        // leaf(80d) + intermediate(20d): depth 2, incomplete 0(len!=1), weakest = min = 20.
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].cert_chain = vec![leaf_cert(80), leaf_cert(20)];
        });
        let t = r#"target="https://example.com/""#;
        assert!(
            text.contains(&format!("httprove_cert_chain_depth{{{t}}} 2")),
            "got:\n{text}"
        );
        assert!(text.contains(&format!("httprove_cert_chain_incomplete{{{t}}} 0")));
        assert!(text.contains(&format!("httprove_cert_weakest_expiry_days{{{t}}} 20")));
    }

    #[test]
    fn b6_leaf_only_marked_incomplete() {
        // leaf 단독(is_ca=false, issuer!=subject): depth 1, incomplete 1.
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].cert_chain = vec![leaf_cert(42)];
        });
        let t = r#"target="https://example.com/""#;
        assert!(text.contains(&format!("httprove_cert_chain_depth{{{t}}} 1")));
        assert!(
            text.contains(&format!("httprove_cert_chain_incomplete{{{t}}} 1")),
            "got:\n{text}"
        );
        assert!(text.contains(&format!("httprove_cert_weakest_expiry_days{{{t}}} 42")));
    }

    #[test]
    fn b6_weakest_expiry_can_be_negative() {
        // 만료된 cert가 섞이면 weakest는 음수를 그대로 노출(만료 탐지에 필요).
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].cert_chain = vec![leaf_cert(50), leaf_cert(-3)];
        });
        let t = r#"target="https://example.com/""#;
        assert!(
            text.contains(&format!("httprove_cert_weakest_expiry_days{{{t}}} -3")),
            "got:\n{text}"
        );
    }

    #[test]
    fn b5_tls_info_present() {
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].tls = Some(tls_info(Some("h2"), Some("X25519")));
        });
        assert!(
            text.contains(
                r#"httprove_tls_info{target="https://example.com/",version="TLSv1.3",cipher="TLS13_AES_128_GCM_SHA256",kx_group="X25519",alpn="h2"} 1"#
            ),
            "got:\n{text}"
        );
    }

    #[test]
    fn b5_tls_info_none_labels_are_empty() {
        // alpn/kx_group None → 빈 문자열 레이블(레이블 집합은 항상 동일하게 유지).
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].tls = Some(tls_info(None, None));
        });
        assert!(
            text.contains(
                r#"httprove_tls_info{target="https://example.com/",version="TLSv1.3",cipher="TLS13_AES_128_GCM_SHA256",kx_group="",alpn=""} 1"#
            ),
            "got:\n{text}"
        );
    }

    #[test]
    fn b5_tls_info_omitted_for_http_target() {
        // tls 없는(http) 마지막 성공: tls_info 섹션 자체가 생략된다.
        let target = "http://plain.example/";
        let ok = ok_probe(target, 0, 12.0, false, 64); // with_dns_tls=false → tls None
        let mut stats = StatsCollector::new();
        stats.record(&ok);
        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: Some(&ok),
            verdict_state: None,
        }];
        let text = render(&tm);
        assert!(!text.contains("httprove_tls_info"), "got:\n{text}");
    }

    #[test]
    fn b14_server_timing_sorted_deduped_filtered() {
        // 중복 metric은 last-wins, 출력은 이름 오름차순. dur 없는/음수 엔트리는 무라인.
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].response_headers = vec![
                (
                    "Server-Timing".to_string(),
                    "db;dur=120, cache;dur=8".to_string(),
                ),
                ("server-timing".to_string(), "db;dur=99".to_string()), // 중복 db → 99
                ("Server-Timing".to_string(), "miss".to_string()),      // dur 없음
                ("Server-Timing".to_string(), "bad;dur=-3".to_string()), // 음수
            ];
        });
        let t = r#"target="https://example.com/""#;
        assert!(
            text.contains(&format!(
                r#"httprove_server_timing_milliseconds{{{t},metric="cache"}} 8"#
            )),
            "got:\n{text}"
        );
        assert!(text.contains(&format!(
            r#"httprove_server_timing_milliseconds{{{t},metric="db"}} 99"#
        )));
        assert!(!text.contains(r#"metric="miss""#));
        assert!(!text.contains(r#"metric="bad""#));
        // BTreeMap 정렬: cache 라인이 db 라인보다 앞.
        let cache_pos = text.find(r#"metric="cache""#).unwrap();
        let db_pos = text.find(r#"metric="db""#).unwrap();
        assert!(cache_pos < db_pos, "cache must precede db:\n{text}");
    }

    #[test]
    fn b14_server_timing_preserves_fractional_dur() {
        // f64 Display 계약 고정: 53.2 → "53.2" (미래에 {v:.0}로 바꾸는 회귀 방지).
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].response_headers =
                vec![("Server-Timing".to_string(), "render;dur=53.2".to_string())];
        });
        assert!(
            text.contains(r#"httprove_server_timing_milliseconds{target="https://example.com/",metric="render"} 53.2"#),
            "got:\n{text}"
        );
    }

    #[test]
    fn v03_snapshot_metrics_omitted_without_success() {
        // 마지막 성공이 없으면 v0.3 스냅샷 메트릭 5종은 헤더째 생략.
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target: "https://x.example/",
            stats: &stats,
            last_success: None,
            verdict_state: None,
        }];
        let text = render(&tm);
        assert!(!text.contains("httprove_cert_chain_depth"));
        assert!(!text.contains("httprove_cert_chain_incomplete"));
        assert!(!text.contains("httprove_cert_weakest_expiry_days"));
        assert!(!text.contains("httprove_tls_info"));
        assert!(!text.contains("httprove_server_timing_milliseconds"));
    }

    // === v0.3 PR-2: B7(throughput) / B9(reuse·version) / B11(dns) render ===

    #[test]
    fn b7_throughput_section_rendered() {
        // render_last 헬퍼: download_ms=5.0(고정) + body 10000 → 2_000_000 bytes/s.
        let target = "https://example.com/";
        let text = render_last(target, |p| {
            p.hops[0].body_bytes = 10_000;
        });
        let t = r#"target="https://example.com/""#;
        assert!(
            text.contains(&format!(
                r#"httprove_throughput_bytes_per_second{{{t},stat="min"}} 2000000"#
            )),
            "got:\n{text}"
        );
    }

    #[test]
    fn b9_reuse_ratio_and_version_rendered() {
        let target = "https://example.com/";
        let mut stats = StatsCollector::new();
        stats.record(&ok_probe(target, 0, 10.0, true, 0)); // 새 연결, HTTP/1.1
        let mut reused = ok_probe(target, 1, 8.0, true, 0);
        reused.hops[0].reused_conn = true;
        reused.hops[0].http_version = "HTTP/2".to_string();
        stats.record(&reused);
        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: Some(&reused),
            verdict_state: None,
        }];
        let text = render(&tm);
        let t = r#"target="https://example.com/""#;
        assert!(
            text.contains(&format!("httprove_hops_total{{{t}}} 2")),
            "got:\n{text}"
        );
        assert!(text.contains(&format!("httprove_connection_reused_total{{{t}}} 1")));
        assert!(text.contains(&format!("httprove_connection_reuse_ratio{{{t}}} 0.5")));
        assert!(text.contains(&format!(
            r#"httprove_http_version_total{{{t},version="http1.1"}} 1"#
        )));
        assert!(text.contains(&format!(
            r#"httprove_http_version_total{{{t},version="http2"}} 1"#
        )));
    }

    #[test]
    fn b9_counters_zero_ratio_and_version_omitted_without_hops() {
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target: "https://x.example/",
            stats: &stats,
            last_success: None,
            verdict_state: None,
        }];
        let text = render(&tm);
        // counter는 stats 기반이라 0이라도 출력(단조 시작점).
        assert!(text.contains(r#"httprove_hops_total{target="https://x.example/"} 0"#));
        assert!(
            text.contains(r#"httprove_connection_reused_total{target="https://x.example/"} 0"#)
        );
        // hop 없음 → ratio(0/0)·version 섹션 생략.
        assert!(!text.contains("httprove_connection_reuse_ratio"));
        assert!(!text.contains("httprove_http_version_total"));
    }

    #[test]
    fn b11_dns_metrics_rendered() {
        let target = "https://example.com/";
        let mut stats = StatsCollector::new();
        let mut p = ok_probe(target, 0, 10.0, true, 0);
        p.hops[0].resolved_ips = vec![
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "2.2.2.2".parse::<IpAddr>().unwrap(),
        ];
        stats.record(&p);
        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: Some(&p),
            verdict_state: None,
        }];
        let text = render(&tm);
        let t = r#"target="https://example.com/""#;
        // counter는 0(첫 baseline), gauge는 IP 수 2.
        assert!(
            text.contains(&format!("httprove_dns_answer_changed_total{{{t}}} 0")),
            "got:\n{text}"
        );
        assert!(text.contains(&format!("httprove_dns_resolved_ip_count{{{t}}} 2")));
    }

    #[test]
    fn b11_counter_emitted_gauge_omitted_without_success() {
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target: "https://x.example/",
            stats: &stats,
            last_success: None,
            verdict_state: None,
        }];
        let text = render(&tm);
        // counter는 stats 기반이라 0이라도 출력, gauge는 last_success 없으면 생략.
        assert!(
            text.contains(r#"httprove_dns_answer_changed_total{target="https://x.example/"} 0"#)
        );
        assert!(!text.contains("httprove_dns_resolved_ip_count"));
    }

    // === v0.3 PR-3+4: B13(verdict_state) / B12(fleet rollup·targets) render ===

    #[test]
    fn b13_verdict_state_active_is_one_rest_zero() {
        let target = "https://example.com/";
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target,
            stats: &stats,
            last_success: None,
            verdict_state: Some(VerdictState::Degraded),
        }];
        let text = render(&tm);
        let t = r#"target="https://example.com/""#;
        assert!(
            text.contains(&format!(
                r#"httprove_verdict_state{{{t},state="degraded"}} 1"#
            )),
            "got:\n{text}"
        );
        assert!(text.contains(&format!(r#"httprove_verdict_state{{{t},state="pass"}} 0"#)));
        assert!(text.contains(&format!(r#"httprove_verdict_state{{{t},state="down"}} 0"#)));
        // 노출 포맷이 Prometheus라 stateset이 아니라 gauge TYPE으로 나가야 한다.
        assert!(text.contains("# TYPE httprove_verdict_state gauge"));
    }

    #[test]
    fn b13_verdict_state_omitted_when_none() {
        let stats = StatsCollector::new();
        let tm = [TargetMetrics {
            target: "https://x.example/",
            stats: &stats,
            last_success: None,
            verdict_state: None,
        }];
        let text = render(&tm);
        assert!(!text.contains("httprove_verdict_state"));
    }

    #[test]
    fn b12_targets_total_down_and_per_target_up() {
        // 3 타깃: pass / degraded / down → total 3, down 1, up = 1/1/0.
        let s = StatsCollector::new();
        let tm = [
            TargetMetrics {
                target: "https://a.example/",
                stats: &s,
                last_success: None,
                verdict_state: Some(VerdictState::Pass),
            },
            TargetMetrics {
                target: "https://b.example/",
                stats: &s,
                last_success: None,
                verdict_state: Some(VerdictState::Degraded),
            },
            TargetMetrics {
                target: "https://c.example/",
                stats: &s,
                last_success: None,
                verdict_state: Some(VerdictState::Down),
            },
        ];
        let text = render(&tm);
        assert!(text.contains("httprove_targets_total 3"), "got:\n{text}");
        assert!(text.contains("httprove_targets_down 1"));
        assert!(text.contains(r#"httprove_target_up{target="https://a.example/"} 1"#));
        assert!(text.contains(r#"httprove_target_up{target="https://b.example/"} 1"#)); // degraded=up
        assert!(text.contains(r#"httprove_target_up{target="https://c.example/"} 0"#)); // down
    }

    #[test]
    fn b12_scalars_emitted_for_empty_targets() {
        // 타깃이 하나도 없어도 targets_total/down 0으로 출력(전 타깃 소실 알림용).
        let text = render(&[]);
        assert!(text.contains("httprove_targets_total 0"), "got:\n{text}");
        assert!(text.contains("httprove_targets_down 0"));
    }

    #[test]
    fn b12_fleet_rollup_worst_best() {
        // 두 타깃의 total 단일 샘플 10/30 → worst(max)=30, best(min)=10.
        let mut sa = StatsCollector::new();
        sa.record(&ok_probe("https://a.example/", 0, 10.0, false, 0));
        let mut sb = StatsCollector::new();
        sb.record(&ok_probe("https://b.example/", 0, 30.0, false, 0));
        let tm = [
            TargetMetrics {
                target: "https://a.example/",
                stats: &sa,
                last_success: None,
                verdict_state: None,
            },
            TargetMetrics {
                target: "https://b.example/",
                stats: &sb,
                last_success: None,
                verdict_state: None,
            },
        ];
        let text = render(&tm);
        assert!(
            text.contains(
                r#"httprove_fleet_phase_milliseconds{phase="total",stat="p50",agg="worst"} 30"#
            ),
            "got:\n{text}"
        );
        assert!(text.contains(
            r#"httprove_fleet_phase_milliseconds{phase="total",stat="p50",agg="best"} 10"#
        ));
    }
}
