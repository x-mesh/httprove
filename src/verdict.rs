//! 서비스 건강 판정(verdict) + 평이한 언어 설명(explain).
//!
//! ## 목적
//! 한 번의 ProbeResult를 SRE가 즉시 이해할 수 있는 한 줄 판정(PASS/DEGRADED/DOWN)과
//! 그 근거 목록으로 요약한다. TUI/단발/요약 출력에서 공통으로 쓰인다.
//!
//! ## assess(result, ctx) -> Verdict
//! 상태(state) 결정 규칙 (위에서부터 우선):
//! 1. `result.error.is_some()`                       => Down
//! 2. 아래 중 하나라도 해당하면                       => Degraded
//!    - `result.expect_failures`가 비어 있지 않음 (어설션 위반)
//!    - 어떤 단계든 `--warn` 임계값 초과: `WarnLevel::of(value, threshold) != Ok`.
//!      비교 대상 값은 `result.summed_timings()`의 각 단계
//!      (dns_ms/tcp_ms/tls_ms/ttfb_ms/download_ms/total_ms)이고,
//!      임계값은 `ctx.warn`의 대응 필드다. dns/tls는 Option이므로 None이면 건너뛴다.
//!    - leaf 인증서 `days_remaining < ctx.cert_warn_days`
//!      (leaf_cert()가 None이면 cert 사유 없음)
//!    - `ctx.baseline_total_ms`가 Some(b)이고 `result.total_ms > 1.5 * b`
//! 3. 그 외                                           => Pass
//!
//! ### headline
//! - 가장 심각한(worst) 신호 하나를 숫자와 함께 한 줄로 표현한다.
//!   - Down이면 실패 단계와 메시지 (예: "DOWN: TLS handshake failed").
//!   - Degraded면 가장 큰 초과를 보이는 신호를 고른다.
//!     예: "TTFB 412ms exceeds warn 200ms (2.1x)",
//!     "cert expires in 5 days (warn < 30)",
//!     "total 980ms vs baseline 420ms (+133%)",
//!     "expectation failed: status 503 not in [200]".
//!     worst 선정: 임계값 대비 비율(value/threshold)이 가장 큰 신호, 또는
//!     baseline 대비 초과율이 더 크면 그쪽을 택한다. 합리적 우선순위면 충분.
//!   - Pass면 핵심 수치 요약 (예: "status 200, total 117ms").
//!
//! ### reasons
//! - state에 기여한 모든 요인을 한 줄씩 나열한다 (headline과 중복돼도 무방).
//!   각 줄은 사람이 읽을 수 있는 영어 문장/구. 비어 있을 수 있다(Pass + 무근거).
//!
//! ## explain(result) -> String
//! - 결과를 인과적으로 풀어 쓴 한 문장(plain language)을 만든다.
//!   성공 예: "Connected to 93.184.216.34 in 31ms, server responded 200 after
//!   51ms (TTFB), total 117ms over HTTP/2 + TLSv1.3."
//!   실패 예: "Failed during the TLS phase: handshake failed — the server's
//!   certificate could not be verified."
//!   error.hint가 있으면 덧붙인다. final_hop()/leaf_cert()/status()를 활용.
//!
//! ## 구현 메모
//! - 패닉 금지: hops가 비어 있거나 cert가 없어도 안전하게 처리한다.
//! - 숫자 포맷은 정수 ms 반올림 권장(예: format!("{:.0}", ms))으로 출력 노이즈를 줄인다.
//! - 색상은 호출처(출력 모듈)가 입힌다 — 여기서는 순수 문자열만 만든다.

use crate::types::{ProbeResult, Verdict, VerdictState, WarnLevel, WarnThresholds};

/// baseline 대비 Degraded로 판정하는 배수 (1.5배 초과).
const BASELINE_DEGRADE_FACTOR: f64 = 1.5;

/// assess에 필요한 임계/기준 컨텍스트.
pub struct VerdictContext {
    /// `--warn phase=ms` 임계값.
    pub warn: WarnThresholds,
    /// 인증서 만료 경고 임계값 (일). days_remaining이 이보다 작으면 Degraded.
    pub cert_warn_days: i64,
    /// 비교 기준 total_ms (baseline/--compare 등). Some이고 1.5배 초과면 Degraded.
    pub baseline_total_ms: Option<f64>,
}

/// Degraded 신호 하나. worst 선정을 위해 정렬용 severity(클수록 심각)를 함께 들고 다닌다.
struct Signal {
    /// reasons/headline에 그대로 쓰는 사람이 읽을 한 줄.
    text: String,
    /// 심각도 정렬 키. 임계값 대비 비율(value/threshold)이거나 baseline 초과 배수.
    /// 어설션 위반처럼 비율이 없는 신호는 아래 우선순위 상수를 쓴다.
    severity: f64,
}

/// 어설션 위반은 임계 비율로 환산되지 않으므로, worst 비교 시 임계값을 막
/// 넘긴 신호(severity≈1.0)보다는 우선하되 명백한 초과는 양보하도록 중간값을 준다.
const EXPECT_FAIL_SEVERITY: f64 = 1.5;

/// 한 프로브 결과를 PASS/DEGRADED/DOWN 판정 + 근거로 요약한다.
pub fn assess(result: &ProbeResult, ctx: &VerdictContext) -> Verdict {
    // 1. 네트워크 실패 => Down. headline은 실패 단계 + 메시지.
    if let Some(err) = &result.error {
        let timeout = if err.timed_out { " (timed out)" } else { "" };
        // headline은 상태 라벨(DOWN)을 포함하지 않는다 — 렌더러가 "DOWN — " 접두를 붙이므로
        // 중복("DOWN — DOWN: ...")을 피한다.
        let headline = format!("{} failed{} — {}", err.phase, timeout, err.message);
        let mut reasons = vec![format!(
            "probe failed during the {} phase: {}",
            err.phase, err.message
        )];
        if let Some(hint) = &err.hint {
            reasons.push(hint.clone());
        }
        return Verdict {
            state: VerdictState::Down,
            headline,
            reasons,
        };
    }

    // error가 없는데 hop도 없으면(손상된 replay/diff 입력 등) 도달했다고 볼 근거가 없다.
    // 신호 0개로 PASS "ok"가 되어버리는 오분류를 막고 Down으로 처리한다.
    if result.final_hop().is_none() {
        return Verdict {
            state: VerdictState::Down,
            headline: "no response recorded (no hops)".to_string(),
            reasons: vec!["probe produced no hops and no error".to_string()],
        };
    }

    // 2. Degraded 신호 수집.
    let mut signals: Vec<Signal> = Vec::new();

    // 2a. --expect 어설션 위반.
    for reason in &result.expect_failures {
        signals.push(Signal {
            text: format!("expectation failed: {reason}"),
            severity: EXPECT_FAIL_SEVERITY,
        });
    }

    // 2b. --warn 임계값 초과 단계. summed_timings 기준, dns/tls는 Option.
    let t = result.summed_timings();
    let warn = &ctx.warn;
    let phase_checks: [(&str, Option<f64>, Option<f64>); 6] = [
        ("DNS", t.dns_ms, warn.dns),
        ("TCP", Some(t.tcp_ms), warn.tcp),
        ("TLS", t.tls_ms, warn.tls),
        ("TTFB", Some(t.ttfb_ms), warn.ttfb),
        ("download", Some(t.download_ms), warn.download),
        ("total", Some(t.total_ms), warn.total),
    ];
    for (label, value, threshold) in phase_checks {
        // 값이 없는 단계(dns/tls None)는 건너뛴다.
        let Some(value) = value else { continue };
        let Some(threshold) = threshold else { continue };
        if threshold > 0.0 && WarnLevel::of(value, Some(threshold)) != WarnLevel::Ok {
            let ratio = value / threshold;
            signals.push(Signal {
                text: format!(
                    "{label} {:.0}ms exceeds warn {:.0}ms ({:.1}x)",
                    value, threshold, ratio
                ),
                severity: ratio,
            });
        }
    }

    // 2c. leaf 인증서 만료 임박.
    if let Some(cert) = result.leaf_cert()
        && cert.days_remaining < ctx.cert_warn_days
    {
        // severity: 만료가 가까울수록(days_remaining이 작을수록) 심각.
        // cert_warn_days를 기준으로 1.0(막 임박)~크게(이미 만료) 환산.
        let severity = if ctx.cert_warn_days > 0 {
            // days_remaining=warn-1 → 약 1.0배, 0 → cert_warn_days배, 음수 → 그 이상.
            (ctx.cert_warn_days - cert.days_remaining) as f64 / ctx.cert_warn_days as f64 + 1.0
        } else {
            // 임계값이 0 이하면 만료(음수)만 잡힌다 — 충분히 심각.
            2.0
        };
        let text = if cert.days_remaining < 0 {
            format!(
                "cert expired {} days ago (warn < {})",
                -cert.days_remaining, ctx.cert_warn_days
            )
        } else {
            format!(
                "cert expires in {} days (warn < {})",
                cert.days_remaining, ctx.cert_warn_days
            )
        };
        signals.push(Signal { text, severity });
    }

    // 2d. baseline 대비 total 초과.
    if let Some(base) = ctx.baseline_total_ms
        && base > 0.0
        && result.total_ms > BASELINE_DEGRADE_FACTOR * base
    {
        let pct = (result.total_ms / base - 1.0) * 100.0;
        signals.push(Signal {
            text: format!(
                "total {:.0}ms vs baseline {:.0}ms (+{:.0}%)",
                result.total_ms, base, pct
            ),
            // baseline 초과 배수를 severity로.
            severity: result.total_ms / base,
        });
    }

    // 3. 신호가 하나도 없으면 Pass.
    if signals.is_empty() {
        let headline = pass_headline(result);
        return Verdict {
            state: VerdictState::Pass,
            headline,
            reasons: Vec::new(),
        };
    }

    // Degraded: worst(severity 최대) 신호를 headline으로, 전부를 reasons로.
    // 동률이면 먼저 수집된 신호(어설션 > 단계 > cert > baseline 순) 유지.
    let worst = signals
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.severity.total_cmp(&b.severity))
        .map(|(i, _)| i)
        .unwrap_or(0);
    let headline = signals[worst].text.clone();
    let reasons = signals.into_iter().map(|s| s.text).collect();
    Verdict {
        state: VerdictState::Degraded,
        headline,
        reasons,
    }
}

/// Pass 헤드라인: 핵심 수치 한 줄 ("status 200, total 117ms over HTTP/2").
fn pass_headline(result: &ProbeResult) -> String {
    match result.final_hop() {
        Some(hop) => {
            let proto = &hop.http_version;
            format!(
                "status {}, total {:.0}ms over {}",
                hop.status, result.total_ms, proto
            )
        }
        // 계약상 성공이면 hop이 최소 1개지만 방어적으로 처리.
        None => format!("ok, total {:.0}ms", result.total_ms),
    }
}

/// 결과를 인과적으로 풀어 쓴 평이한 한 문장.
pub fn explain(result: &ProbeResult) -> String {
    // 실패: 어느 단계에서 왜 실패했는지 + (있으면) 힌트.
    if let Some(err) = &result.error {
        let timeout = if err.timed_out {
            " (the operation timed out)"
        } else {
            ""
        };
        let mut sentence = format!(
            "Failed during the {} phase: {}{}.",
            err.phase, err.message, timeout
        );
        if let Some(hint) = &err.hint {
            sentence.push(' ');
            sentence.push_str(hint);
        }
        return sentence;
    }

    // 성공: 연결 → 응답 → 전체를 단계 시간과 함께 한 문장으로.
    let Some(hop) = result.final_hop() else {
        // 계약상 도달 불가하나 방어적으로 처리.
        return "Completed with no hops recorded.".to_string();
    };

    let t = result.summed_timings();
    // 연결 시간 = dns + tcp + tls (있는 것만). 재사용 연결이면 0에 가깝다.
    let connect_ms = t.dns_ms.unwrap_or(0.0) + t.tcp_ms + t.tls_ms.unwrap_or(0.0);

    // 프로토콜 + (https면) TLS 버전.
    let proto = match &hop.tls {
        Some(tls) => format!("{} + {}", hop.http_version, tls.version),
        None => hop.http_version.clone(),
    };

    let mut sentence = if hop.reused_conn {
        // keep-alive 재사용: 연결 단계가 없으므로 응답 중심으로 서술.
        format!(
            "Reused connection to {}, server responded {} after {:.0}ms (TTFB), total {:.0}ms over {}.",
            hop.ip, hop.status, t.ttfb_ms, result.total_ms, proto
        )
    } else {
        format!(
            "Connected to {} in {:.0}ms, server responded {} after {:.0}ms (TTFB), total {:.0}ms over {}.",
            hop.ip, connect_ms, hop.status, t.ttfb_ms, result.total_ms, proto
        )
    };

    // 리다이렉트가 있었으면 hop 수를 덧붙인다.
    if result.hops.len() > 1 {
        sentence.push_str(&format!(" Followed {} redirects.", result.hops.len() - 1));
    }

    sentence
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::types::{
        CertInfo, ErrorPhase, HopResult, PhaseTimings, ProbeError, ProbeResult, TlsInfo,
        WarnThresholds,
    };

    /// 기본(무경고) 컨텍스트: 임계값 없음, cert 경고 30일, baseline 없음.
    fn ctx() -> VerdictContext {
        VerdictContext {
            warn: WarnThresholds::default(),
            cert_warn_days: 30,
            baseline_total_ms: None,
        }
    }

    /// 성공 프로브 생성 헬퍼. with_tls면 TLS 단계/info를 채운다.
    fn ok_probe(total: f64, ttfb: f64, with_tls: bool) -> ProbeResult {
        let timings = PhaseTimings {
            dns_ms: with_tls.then_some(5.0),
            tcp_ms: 10.0,
            tls_ms: with_tls.then_some(20.0),
            ttfb_ms: ttfb,
            download_ms: 3.0,
            total_ms: total,
        };
        let tls = with_tls.then(|| TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher: "TLS13_AES_128_GCM_SHA256".to_string(),
            alpn: Some("h2".to_string()),
            kx_group: Some("X25519".to_string()),
        });
        ProbeResult {
            target: "https://example.com/".to_string(),
            seq: 0,
            timestamp: Utc::now(),
            hops: vec![HopResult {
                url: "https://example.com/".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 443,
                reused_conn: false,
                local_addr: None,
                resolved_ips: vec![],
                http_version: if with_tls { "HTTP/2" } else { "HTTP/1.1" }.to_string(),
                status: 200,
                timings,
                tls,
                cert_chain: vec![],
                response_headers: vec![],
                body_bytes: 1024,
                redirect_to: None,
            }],
            error: None,
            expect_failures: vec![],
            total_ms: total,
        }
    }

    /// leaf 인증서를 붙여 days_remaining을 지정한다.
    fn with_cert(mut p: ProbeResult, days_remaining: i64) -> ProbeResult {
        let now = Utc::now();
        p.hops[0].cert_chain = vec![CertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Example CA".to_string(),
            san: vec!["example.com".to_string()],
            not_before: now,
            not_after: now + chrono::Duration::days(days_remaining.max(0)),
            days_remaining,
            serial: "01:02:03".to_string(),
            sig_alg: "ECDSA-SHA256".to_string(),
            pubkey: "EC P-256".to_string(),
            is_ca: false,
            spki_sha256: String::new(),
            aia_ca_issuers: None,
        }];
        p
    }

    /// 실패 프로브 생성 헬퍼.
    fn failed_probe(phase: ErrorPhase, message: &str, timed_out: bool) -> ProbeResult {
        let mut p = ok_probe(120.0, 50.0, true);
        p.error = Some(ProbeError {
            phase,
            message: message.to_string(),
            timed_out,
            hint: None,
        });
        p
    }

    // --- 상태 분류 -----------------------------------------------------------

    #[test]
    fn classifies_pass_when_all_signals_ok() {
        let v = assess(&ok_probe(117.0, 51.0, true), &ctx());
        assert_eq!(v.state, VerdictState::Pass);
        assert!(v.reasons.is_empty());
        // 핵심 수치가 headline에 들어간다.
        assert!(v.headline.contains("200"), "headline: {}", v.headline);
        assert!(v.headline.contains("117"), "headline: {}", v.headline);
    }

    #[test]
    fn classifies_down_on_error() {
        let v = assess(
            &failed_probe(ErrorPhase::Tls, "handshake failed", false),
            &ctx(),
        );
        assert_eq!(v.state, VerdictState::Down);
        // headline은 상태 라벨 접두 없이 실패 단계+메시지만 담는다 (렌더러가 "DOWN — "를 붙임).
        assert!(v.headline.contains("tls"), "headline: {}", v.headline);
        assert!(
            v.headline.contains("handshake failed"),
            "headline: {}",
            v.headline
        );
        assert!(!v.reasons.is_empty());
    }

    #[test]
    fn down_error_includes_hint_in_reasons() {
        let mut p = failed_probe(ErrorPhase::Tls, "invalid peer certificate", false);
        if let Some(err) = &mut p.error {
            err.hint = Some("Server certificate has expired — renew it.".to_string());
        }
        let v = assess(&p, &ctx());
        assert_eq!(v.state, VerdictState::Down);
        assert!(v.reasons.iter().any(|r| r.contains("renew")));
    }

    #[test]
    fn timed_out_error_is_marked() {
        let v = assess(
            &failed_probe(ErrorPhase::Tcp, "connection timed out", true),
            &ctx(),
        );
        assert_eq!(v.state, VerdictState::Down);
        assert!(v.headline.contains("timed out"), "headline: {}", v.headline);
    }

    #[test]
    fn classifies_degraded_on_expect_failure() {
        let mut p = ok_probe(117.0, 51.0, true);
        p.expect_failures = vec!["status 503 not in [200]".to_string()];
        let v = assess(&p, &ctx());
        assert_eq!(v.state, VerdictState::Degraded);
        assert!(
            v.headline.contains("expectation failed"),
            "headline: {}",
            v.headline
        );
        assert!(v.reasons.iter().any(|r| r.contains("503")));
    }

    #[test]
    fn classifies_degraded_on_warn_breach() {
        // TTFB 420ms, warn 200ms => 2.1x 초과.
        let p = ok_probe(500.0, 420.0, true);
        let mut c = ctx();
        c.warn.ttfb = Some(200.0);
        let v = assess(&p, &c);
        assert_eq!(v.state, VerdictState::Degraded);
        assert!(v.headline.contains("TTFB"), "headline: {}", v.headline);
        assert!(v.headline.contains("420"), "headline: {}", v.headline);
        assert!(v.headline.contains("warn 200"), "headline: {}", v.headline);
    }

    #[test]
    fn classifies_degraded_on_cert_near_expiry() {
        let p = with_cert(ok_probe(117.0, 51.0, true), 5);
        let v = assess(&p, &ctx()); // cert_warn_days = 30
        assert_eq!(v.state, VerdictState::Degraded);
        assert!(
            v.headline.contains("cert expires in 5 days"),
            "headline: {}",
            v.headline
        );
    }

    #[test]
    fn cert_well_within_validity_is_pass() {
        let p = with_cert(ok_probe(117.0, 51.0, true), 200);
        let v = assess(&p, &ctx());
        assert_eq!(v.state, VerdictState::Pass);
    }

    #[test]
    fn expired_cert_reports_days_ago() {
        let p = with_cert(ok_probe(117.0, 51.0, true), -3);
        let v = assess(&p, &ctx());
        assert_eq!(v.state, VerdictState::Degraded);
        assert!(
            v.headline.contains("expired 3 days ago"),
            "headline: {}",
            v.headline
        );
    }

    #[test]
    fn classifies_degraded_on_baseline_breach() {
        // total 980 > 1.5 * 420 = 630 => Degraded.
        let p = ok_probe(980.0, 100.0, true);
        let mut c = ctx();
        c.baseline_total_ms = Some(420.0);
        let v = assess(&p, &c);
        assert_eq!(v.state, VerdictState::Degraded);
        assert!(
            v.headline.contains("baseline 420"),
            "headline: {}",
            v.headline
        );
    }

    #[test]
    fn baseline_within_1_5x_is_pass() {
        // total 600 <= 1.5 * 420 = 630 => Pass.
        let p = ok_probe(600.0, 100.0, true);
        let mut c = ctx();
        c.baseline_total_ms = Some(420.0);
        let v = assess(&p, &c);
        assert_eq!(v.state, VerdictState::Pass);
    }

    #[test]
    fn worst_signal_wins_headline_and_all_in_reasons() {
        // TTFB 막 초과(1.05x)와 cert 거의 만료(1일)를 동시에 — cert가 더 심각해야 한다.
        let mut p = with_cert(ok_probe(500.0, 210.0, true), 1);
        let _ = &mut p;
        let mut c = ctx();
        c.warn.ttfb = Some(200.0); // 210/200 = 1.05x
        let v = assess(&p, &c);
        assert_eq!(v.state, VerdictState::Degraded);
        // cert severity(≈30/30+1=30)가 TTFB(1.05x)보다 훨씬 크므로 headline은 cert.
        assert!(
            v.headline.contains("cert expires"),
            "headline: {}",
            v.headline
        );
        // 두 신호 모두 reasons에 들어간다.
        assert_eq!(v.reasons.len(), 2);
        assert!(v.reasons.iter().any(|r| r.contains("TTFB")));
        assert!(v.reasons.iter().any(|r| r.contains("cert")));
    }

    // --- explain -------------------------------------------------------------

    #[test]
    fn explain_success_walks_phases() {
        let s = explain(&ok_probe(117.0, 51.0, true));
        assert!(s.contains("Connected to 93.184.216.34"), "{s}");
        assert!(s.contains("200"), "{s}");
        assert!(s.contains("(TTFB)"), "{s}");
        assert!(s.contains("HTTP/2"), "{s}");
        assert!(s.contains("TLSv1.3"), "{s}");
    }

    #[test]
    fn explain_failure_describes_phase_and_hint() {
        let mut p = failed_probe(ErrorPhase::Tls, "handshake failed", false);
        if let Some(err) = &mut p.error {
            err.hint = Some("The certificate could not be verified.".to_string());
        }
        let s = explain(&p);
        assert!(s.contains("Failed during the tls phase"), "{s}");
        assert!(s.contains("handshake failed"), "{s}");
        assert!(s.contains("could not be verified"), "{s}");
    }

    #[test]
    fn explain_reused_connection_mentions_reuse() {
        let mut p = ok_probe(40.0, 30.0, true);
        p.hops[0].reused_conn = true;
        let s = explain(&p);
        assert!(s.contains("Reused connection"), "{s}");
    }
}
