//! 베이스라인 저장/비교 (`--save` / `--compare`).
//!
//! ## 파일 포맷 (JSON, pretty 아님)
//! ```json
//! {"version":1,"created_at":"2026-06-13T01:00:00Z","targets":[
//!   {"target":"https://example.com/","probes":10,
//!    "phases":{"dns":{PhaseStats...},"total":{...}},
//!    "cert_days":78}]}
//! ```
//! - phases 키는 stats::Phase::label() 값. 샘플 없는 단계는 생략.
//! - cert_days: 마지막 관측 leaf 인증서 잔여 일수 (없으면 null).
//!
//! ## 비교 출력 (print_comparison)
//! 타깃별로 (베이스라인과 현재 양쪽에 있는 타깃만, 한쪽에만 있으면 그렇다고 한 줄):
//! ```text
//! --- compare vs baseline.json (saved 2026-06-12T10:00:00Z) ---
//! https://example.com/
//! phase      metric   baseline    current      delta
//! ttfb       p50        51.2ms     48.9ms      -4.5%
//! ttfb       p95        80.1ms    103.2ms     +28.8%   ← 빨강
//! total      p50       117.6ms    110.2ms      -6.3%
//! total      p95       190.0ms    170.0ms     -10.5%   ← 초록
//! ```
//! - 단계별로 p50, p95 두 행 (양쪽 모두 해당 단계가 있을 때만).
//! - delta% = (current - baseline) / baseline * 100. baseline이 0이면 "-" 표시.
//! - 색상(color=true일 때): delta >= +10% 빨강, <= -10% 초록, 그 외 무색.
//! - cert_days가 줄었으면 마지막에 한 줄: "cert: 78d → 41d".
//!
//! 저장/로드 에러는 anyhow로 전파 (호출측 main이 메시지 출력).

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use colored::{ColoredString, Colorize};
use serde::{Deserialize, Serialize};

use crate::stats::{Phase, PhaseStats, StatsCollector};

/// 현재 지원하는 베이스라인 파일 포맷 버전.
const BASELINE_VERSION: u32 = 1;

/// delta 강조 임계값 (%). 이 이상 증가 → 빨강, 이 이상 감소 → 초록.
const DELTA_HIGHLIGHT_PCT: f64 = 10.0;

/// 비교 테이블 컬럼 폭 (스펙 고정값).
const COL_PHASE: usize = 11;
const COL_METRIC: usize = 9;
const COL_BASELINE: usize = 8;
const COL_CURRENT: usize = 11;
const COL_DELTA: usize = 11;

/// 베이스라인 파일 루트.
#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub targets: Vec<TargetBaseline>,
}

/// 타깃 하나의 스냅샷.
#[derive(Debug, Serialize, Deserialize)]
pub struct TargetBaseline {
    pub target: String,
    pub probes: u64,
    pub phases: BTreeMap<String, PhaseStats>,
    pub cert_days: Option<i64>,
}

/// 현재 통계로 Baseline을 만든다. targets 순서 보존.
pub fn build(targets: &[(String, &StatsCollector, Option<i64>)]) -> Baseline {
    let targets = targets
        .iter()
        .map(|(name, stats, cert_days)| {
            // 샘플이 있는 단계만 스냅샷에 포함 (예: http 대상은 dns/tls 생략).
            let mut phases = BTreeMap::new();
            for phase in Phase::ALL {
                if let Some(s) = stats.phase_stats(phase) {
                    phases.insert(phase.label().to_string(), s);
                }
            }
            TargetBaseline {
                target: name.clone(),
                probes: stats.sent(),
                phases,
                cert_days: *cert_days,
            }
        })
        .collect();

    Baseline {
        version: BASELINE_VERSION,
        created_at: Utc::now(),
        targets,
    }
}

/// 파일로 저장 (JSON 한 덩어리 + 개행).
pub fn save(path: &str, baseline: &Baseline) -> anyhow::Result<()> {
    let mut json =
        serde_json::to_string(baseline).context("failed to serialize baseline to JSON")?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("failed to write baseline file {path}"))?;
    Ok(())
}

/// 파일에서 로드 (version 불일치는 에러).
pub fn load(path: &str) -> anyhow::Result<Baseline> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline file {path}"))?;
    let baseline: Baseline = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse baseline file {path}"))?;
    if baseline.version != BASELINE_VERSION {
        bail!(
            "baseline file {path} has unsupported version {} (expected {BASELINE_VERSION})",
            baseline.version
        );
    }
    Ok(baseline)
}

/// 베이스라인 vs 현재 비교 테이블 출력. path는 표시용 파일명.
pub fn print_comparison(path: &str, base: &Baseline, current: &Baseline, color: bool) {
    let saved = base.created_at.format("%Y-%m-%dT%H:%M:%SZ");
    println!("--- compare vs {path} (saved {saved}) ---");

    // 현재 실행 순서대로: 양쪽에 있으면 비교 블록, 현재에만 있으면 한 줄 안내.
    // 안내 줄도 빈 줄로 구분해 앞 블록의 마지막 행에 붙어 보이지 않게 한다.
    let mut first_item = true;
    for cur in &current.targets {
        if !first_item {
            println!();
        }
        first_item = false;
        let Some(b) = base.targets.iter().find(|b| b.target == cur.target) else {
            let line = format!("target {}: not in baseline", cur.target);
            println!("{}", paint(&line, color, |s| s.dimmed()));
            continue;
        };
        print_target_block(b, cur, color);
    }

    // 베이스라인에만 있는 타깃도 한 줄로 알린다.
    for b in &base.targets {
        if !current.targets.iter().any(|c| c.target == b.target) {
            let line = format!("target {}: not in current run", b.target);
            println!("{}", paint(&line, color, |s| s.dimmed()));
        }
    }
}

/// 타깃 하나의 비교 블록 (타깃 이름 + 테이블 + 선택적 cert 줄).
fn print_target_block(base: &TargetBaseline, cur: &TargetBaseline, color: bool) {
    println!("{}", cur.target);
    println!(
        "{:<pw$}{:<mw$}{:>bw$}{:>cw$}{:>dw$}",
        "phase",
        "metric",
        "baseline",
        "current",
        "delta",
        pw = COL_PHASE,
        mw = COL_METRIC,
        bw = COL_BASELINE,
        cw = COL_CURRENT,
        dw = COL_DELTA,
    );

    // 양쪽 모두 해당 단계 통계가 있을 때만 p50/p95 두 행 출력.
    for phase in Phase::ALL {
        let label = phase.label();
        let (Some(bs), Some(cs)) = (base.phases.get(label), cur.phases.get(label)) else {
            continue;
        };
        for (metric, bv, cv) in [("p50", bs.p50, cs.p50), ("p95", bs.p95, cs.p95)] {
            println!("{}", comparison_row(label, metric, bv, cv, color));
        }
    }

    // 인증서 잔여 일수가 줄었을 때만 알린다 (양쪽 모두 관측된 경우).
    if let (Some(bd), Some(cd)) = (base.cert_days, cur.cert_days)
        && cd < bd
    {
        println!("cert: {bd}d → {cd}d");
    }
}

/// 비교 테이블 한 행. delta 셀만 임계값에 따라 색상 적용.
fn comparison_row(phase: &str, metric: &str, baseline: f64, current: f64, color: bool) -> String {
    // 패딩을 먼저 적용한 뒤 색을 입혀야 ANSI 코드가 폭 계산을 깨지 않는다.
    let delta_cell = format!("{:>dw$}", format_delta(baseline, current), dw = COL_DELTA);
    let delta_cell = match delta_pct(baseline, current) {
        Some(p) if p >= DELTA_HIGHLIGHT_PCT => paint(&delta_cell, color, |s| s.red()),
        Some(p) if p <= -DELTA_HIGHLIGHT_PCT => paint(&delta_cell, color, |s| s.green()),
        _ => delta_cell,
    };
    format!(
        "{:<pw$}{:<mw$}{:>bw$}{:>cw$}{}",
        phase,
        metric,
        format!("{baseline:.1}ms"),
        format!("{current:.1}ms"),
        delta_cell,
        pw = COL_PHASE,
        mw = COL_METRIC,
        bw = COL_BASELINE,
        cw = COL_CURRENT,
    )
}

/// delta% = (current - baseline) / baseline * 100. baseline이 0이면 None (정의 불가).
fn delta_pct(baseline: f64, current: f64) -> Option<f64> {
    if baseline == 0.0 {
        None
    } else {
        Some((current - baseline) / baseline * 100.0)
    }
}

/// delta 표시 문자열: "+28.8%" / "-4.5%", baseline 0이면 "-".
fn format_delta(baseline: f64, current: f64) -> String {
    match delta_pct(baseline, current) {
        Some(p) => format!("{p:+.1}%"),
        None => "-".to_string(),
    }
}

/// color 게이트를 거쳐 색상을 적용한다. 비활성 시 원문 그대로.
fn paint(s: &str, enabled: bool, f: impl FnOnce(&str) -> ColoredString) -> String {
    if enabled {
        f(s).to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use chrono::Utc;

    use super::*;
    use crate::types::{HopResult, PhaseTimings, ProbeResult};

    /// 성공 프로브 생성 헬퍼 (http 대상: dns/tls 단계 없음).
    fn ok_probe(target: &str, seq: u64, total: f64) -> ProbeResult {
        let timings = PhaseTimings {
            dns_ms: None,
            tcp_ms: 2.0,
            tls_ms: None,
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
                port: 80,
                reused_conn: false,
                local_addr: None,
                resolved_ips: vec![],
                http_version: "HTTP/1.1".to_string(),
                status: 200,
                timings,
                tls: None,
                cert_chain: vec![],
                response_headers: vec![],
                body_bytes: 0,
                redirect_to: None,
            }],
            error: None,
            expect_failures: vec![],
            total_ms: total,
        }
    }

    /// 충돌 없는 임시 파일 경로 (pid + 나노초 시각).
    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "httprove-baseline-{tag}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn build_save_load_roundtrip() {
        let mut stats_a = StatsCollector::new();
        for i in 0..5 {
            stats_a.record(&ok_probe("http://a.example/", i, 10.0 + i as f64));
        }
        let stats_b = StatsCollector::new(); // 샘플 없는 타깃.

        let rows: Vec<(String, &StatsCollector, Option<i64>)> = vec![
            ("http://a.example/".to_string(), &stats_a, Some(78)),
            ("http://b.example/".to_string(), &stats_b, None),
        ];
        let built = build(&rows);

        assert_eq!(built.version, 1);
        assert_eq!(built.targets.len(), 2);
        // 순서 보존.
        assert_eq!(built.targets[0].target, "http://a.example/");
        assert_eq!(built.targets[1].target, "http://b.example/");

        let a = &built.targets[0];
        assert_eq!(a.probes, 5);
        assert_eq!(a.cert_days, Some(78));
        // http 프로브: dns/tls 샘플 없음 → phases에서 생략.
        for label in ["tcp", "ttfb", "download", "total"] {
            assert!(a.phases.contains_key(label), "missing {label}");
        }
        assert!(!a.phases.contains_key("dns"));
        assert!(!a.phases.contains_key("tls"));
        // 샘플이 전혀 없는 타깃은 phases가 빈 맵.
        assert!(built.targets[1].phases.is_empty());

        let path = temp_path("roundtrip");
        let path_str = path.to_string_lossy().into_owned();
        save(&path_str, &built).unwrap();
        let loaded = load(&path_str);
        let _ = std::fs::remove_file(&path);
        let loaded = loaded.unwrap();

        assert_eq!(loaded.version, built.version);
        assert_eq!(loaded.created_at, built.created_at);
        assert_eq!(loaded.targets.len(), built.targets.len());
        let la = &loaded.targets[0];
        assert_eq!(la.target, a.target);
        assert_eq!(la.probes, a.probes);
        assert_eq!(la.cert_days, a.cert_days);
        assert_eq!(la.phases.len(), a.phases.len());
        let (orig, back) = (&a.phases["total"], &la.phases["total"]);
        assert_eq!(back.count, orig.count);
        assert_eq!(back.min, orig.min);
        assert_eq!(back.max, orig.max);
        assert_eq!(back.p50, orig.p50);
        assert_eq!(back.p95, orig.p95);
    }

    #[test]
    fn delta_math_edge_cases() {
        // baseline 0 → 비율 정의 불가, "-" 표시 (색상 없음 경로).
        assert_eq!(delta_pct(0.0, 5.0), None);
        assert_eq!(format_delta(0.0, 5.0), "-");
        assert_eq!(format_delta(0.0, 0.0), "-");

        // 스펙 예시 값 그대로 검증.
        assert_eq!(format_delta(80.1, 103.2), "+28.8%");
        assert_eq!(format_delta(51.2, 48.9), "-4.5%");
        // 변화 없음 → 부호 포함 0.
        assert_eq!(format_delta(100.0, 100.0), "+0.0%");

        let p = delta_pct(100.0, 150.0);
        assert!(p.is_some_and(|p| (p - 50.0).abs() < 1e-9));
    }

    #[test]
    fn comparison_row_layout_matches_spec() {
        // 색상 비활성 시 스펙 예시와 자릿수까지 동일해야 한다.
        assert_eq!(
            comparison_row("ttfb", "p95", 80.1, 103.2, false),
            "ttfb       p95        80.1ms    103.2ms     +28.8%"
        );
        assert_eq!(
            comparison_row("total", "p50", 117.6, 110.2, false),
            "total      p50       117.6ms    110.2ms      -6.3%"
        );
    }

    #[test]
    fn load_rejects_version_mismatch() {
        let path = temp_path("version");
        let path_str = path.to_string_lossy().into_owned();
        std::fs::write(
            &path,
            "{\"version\":2,\"created_at\":\"2026-06-13T00:00:00Z\",\"targets\":[]}\n",
        )
        .unwrap();
        let result = load(&path_str);
        let _ = std::fs::remove_file(&path);
        let err = match result {
            Ok(_) => panic!("version 2 must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("version"), "{err}");
    }
}
