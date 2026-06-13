//! Prometheus/OpenMetrics 텍스트 포맷 렌더링.
//!
//! `--prom`(요약 대신 출력, node_exporter textfile collector용)과
//! `--listen`(exporter의 /metrics)이 공용으로 사용한다.
//!
//! ## 메트릭 (모두 target 레이블 포함)
//! - `httprove_probes_total{target}` counter — sent
//! - `httprove_probe_failures_total{target}` counter — failed (네트워크 실패)
//! - `httprove_expect_failures_total{target}` counter — expect_failed
//! - `httprove_phase_milliseconds{target,phase,stat}` gauge —
//!   phase ∈ dns|tcp|tls|ttfb|download|total, stat ∈ min|mean|p50|p95|p99|max
//!   (샘플 없는 단계는 생략)
//! - `httprove_status_total{target,code}` counter — 상태 코드 분포
//! - `httprove_last_total_milliseconds{target}` gauge — 마지막 성공 프로브 total
//! - `httprove_last_body_bytes{target}` gauge — 마지막 성공 프로브 바디 크기(전체 hop 합)
//! - `httprove_cert_expiry_days{target}` gauge — 마지막 관측 leaf 인증서 잔여 일수
//!
//! ## 규칙
//! - 각 메트릭 이름마다 # HELP / # TYPE 헤더를 1회 출력.
//! - 레이블 값 이스케이프: `\` → `\\`, `"` → `\"`, 개행 → `\n`.
//! - counter 메트릭은 누적값 그대로 (StatsCollector가 단조 증가).
//! - 마지막 줄 끝에 개행 포함.

use crate::stats::{Phase, StatsCollector};
use crate::types::ProbeResult;

/// 한 타깃의 메트릭 입력.
pub struct TargetMetrics<'a> {
    /// 타깃 URL 문자열 (target 레이블 값).
    pub target: &'a str,
    pub stats: &'a StatsCollector,
    /// 마지막 성공 ProbeResult (last_* 및 cert 메트릭용, 없으면 해당 메트릭 생략).
    pub last_success: Option<&'a ProbeResult>,
}

/// phase 게이지의 stat 레이블 출력 순서.
const STAT_ORDER: [&str; 6] = ["min", "mean", "p50", "p95", "p99", "max"];

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
            let values = [s.min, s.mean, s.p50, s.p95, s.p99, s.max];
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

    // --- 마지막 성공 프로브 기반 게이지: 성공이 없으면 생략 -------------------
    let mut last_total_lines = Vec::new();
    let mut last_body_lines = Vec::new();
    let mut cert_lines = Vec::new();
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

    out
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::types::{CertInfo, ErrorPhase, HopResult, PhaseTimings, ProbeError, ProbeResult};

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
            },
            TargetMetrics {
                target: "https://b.example/",
                stats: &stats_b,
                last_success: None,
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
}
