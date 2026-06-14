//! 자가 포함(self-contained) HTML 리포트 생성.
//!
//! 담당 기능:
//! - ㉟ 한 번의 실행 결과(여러 ProbeResult + 대응 Verdict)를 외부 에셋 없이 열람 가능한
//!   단일 HTML 파일로 저장한다 (CSS 인라인, JS/이미지/폰트 등 외부 의존 0).
//!
//! ## write_report(results, verdicts, path) -> Result<()>
//! results[i]와 verdicts[i]가 짝을 이룬다(길이가 다르면 가능한 만큼 매칭, 패닉 금지).
//! 생성 HTML 구성:
//! 1. <!doctype html> + <style>...inline CSS...</style> (다크/라이트 무관, 한 테마면 충분).
//! 2. **Verdict 배너**: 각 타깃의 VerdictState를 색상 박스로
//!    (Pass=초록, Degraded=노랑, Down=빨강) + headline + reasons 목록.
//! 3. **워터폴**: 각 프로브의 단계별 시간을 인라인 CSS 막대(div width %)로 시각화
//!    (dns/tcp/tls/ttfb/download). summed_timings 기준, 누적 오프셋으로 폭/위치 계산.
//! 4. **인증서 체인**: leaf/체인 각 cert의 subject/issuer/만료일/남은 일수
//!    (만료 임박/만료는 색상 강조).
//! 5. **Raw 테이블**: seq/timestamp/connected IP/status/HTTP 버전/total 등 핵심 필드 표.
//!
//! 모든 사용자 유래 문자열(헤더 값/subject/URL 등)은 **HTML 이스케이프**한다
//! (& < > " ' 치환 — XSS/깨짐 방지). 작은 escape 헬퍼를 둔다.
//! 파일 쓰기 오류는 anyhow context로 감싼다.
//!
//! ## 구현 메모
//! - 패닉 금지. 빈 results여도 유효한 HTML(빈 상태 안내)을 쓴다.
//! - 외부 링크/CDN/폰트 금지 — 시스템 폰트 스택만. 색상은 인라인 style 또는 <style> 클래스.
//! - 문자열은 format!/String push로 조립(템플릿 엔진 없음).
//! - #[cfg(test)]로 escape 헬퍼와, 산출 문자열에 "<!doctype html>"·배너 텍스트가 포함되는지
//!   가벼운 검증 권장.

use std::fmt::Write as _;

use anyhow::Context;

use crate::types::{CertInfo, PhaseTimings, ProbeResult, Verdict, VerdictState};

/// 실행 결과 + 판정을 단일 자가 포함 HTML 리포트로 파일에 쓴다.
pub fn write_report(
    results: &[ProbeResult],
    verdicts: &[Verdict],
    path: &str,
) -> anyhow::Result<()> {
    let html = render(results, verdicts);
    std::fs::write(path, html).with_context(|| format!("write HTML report to {path}"))
}

/// 전체 HTML 문서를 문자열로 조립한다.
fn render(results: &[ProbeResult], verdicts: &[Verdict]) -> String {
    let mut s = String::with_capacity(8 * 1024);
    s.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    s.push_str("<meta charset=\"utf-8\">\n");
    s.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    s.push_str("<title>httprove report</title>\n");
    s.push_str(STYLE);
    s.push_str("</head>\n<body>\n");

    s.push_str("<header class=\"top\">\n");
    s.push_str("<h1>httprove report</h1>\n");
    let _ = writeln!(s, "<p class=\"meta\">{} target(s)</p>", results.len());
    s.push_str("</header>\n");

    if results.is_empty() {
        s.push_str("<main>\n<p class=\"empty\">No probe results to report.</p>\n</main>\n");
        s.push_str("</body>\n</html>\n");
        return s;
    }

    s.push_str("<main>\n");
    for (i, result) in results.iter().enumerate() {
        let verdict = verdicts.get(i);
        render_section(&mut s, result, verdict);
    }
    s.push_str("</main>\n");

    s.push_str("</body>\n</html>\n");
    s
}

/// 한 프로브 결과 1건의 섹션(배너 + 워터폴 + cert + raw)을 조립한다.
fn render_section(s: &mut String, result: &ProbeResult, verdict: Option<&Verdict>) {
    s.push_str("<section class=\"card\">\n");

    // --- 제목: 타깃 URL ---
    let _ = writeln!(s, "<h2 class=\"target\">{}</h2>", escape(&result.target));

    // --- Verdict 배너 ---
    if let Some(v) = verdict {
        render_banner(s, v);
    }

    // --- 에러(있으면) ---
    if let Some(err) = &result.error {
        s.push_str("<div class=\"errbox\">\n");
        let _ = writeln!(
            s,
            "<strong>{} error:</strong> {}",
            escape(&err.phase.to_string()),
            escape(&err.message)
        );
        if err.timed_out {
            s.push_str(" <span class=\"tag\">timed out</span>");
        }
        if let Some(hint) = &err.hint {
            let _ = writeln!(s, "<div class=\"hint\">{}</div>", escape(hint));
        }
        s.push_str("</div>\n");
    }

    // --- 워터폴 ---
    render_waterfall(s, &result.summed_timings());

    // --- 인증서 체인 ---
    render_cert_chain(s, result);

    // --- Raw 테이블 ---
    render_raw_table(s, result);

    s.push_str("</section>\n");
}

/// VerdictState별 색상 배너.
fn render_banner(s: &mut String, v: &Verdict) {
    let cls = match v.state {
        VerdictState::Pass => "pass",
        VerdictState::Degraded => "degraded",
        VerdictState::Down => "down",
    };
    let _ = writeln!(s, "<div class=\"banner {cls}\">");
    let _ = writeln!(
        s,
        "<span class=\"state\">{}</span>",
        escape(v.state.label())
    );
    let _ = writeln!(s, "<span class=\"headline\">{}</span>", escape(&v.headline));
    s.push_str("</div>\n");
    if !v.reasons.is_empty() {
        s.push_str("<ul class=\"reasons\">\n");
        for r in &v.reasons {
            let _ = writeln!(s, "<li>{}</li>", escape(r));
        }
        s.push_str("</ul>\n");
    }
}

/// 단계별 시간을 비례 폭 막대로 시각화한다.
fn render_waterfall(s: &mut String, t: &PhaseTimings) {
    // 표시할 단계 (이름, ms, css 클래스).
    let mut phases: Vec<(&str, f64, &str)> = Vec::with_capacity(5);
    if let Some(dns) = t.dns_ms {
        phases.push(("DNS", dns.max(0.0), "p-dns"));
    }
    phases.push(("TCP", t.tcp_ms.max(0.0), "p-tcp"));
    if let Some(tls) = t.tls_ms {
        phases.push(("TLS", tls.max(0.0), "p-tls"));
    }
    phases.push(("TTFB", t.ttfb_ms.max(0.0), "p-ttfb"));
    phases.push(("Download", t.download_ms.max(0.0), "p-dl"));

    let total: f64 = phases.iter().map(|(_, ms, _)| *ms).sum();

    s.push_str("<div class=\"waterfall\">\n");
    s.push_str("<h3>Waterfall</h3>\n");

    if total <= 0.0 {
        s.push_str("<p class=\"empty\">No timing data.</p>\n");
        s.push_str("</div>\n");
        return;
    }

    for (name, ms, cls) in &phases {
        let pct = (ms / total) * 100.0;
        // 막대 1행: 라벨 + 비례 폭 div.
        s.push_str("<div class=\"wf-row\">\n");
        let _ = writeln!(s, "<span class=\"wf-label\">{name}</span>");
        s.push_str("<span class=\"wf-track\">");
        // width는 안전한 숫자(이스케이프 불필요). 최소 가시 폭 보장은 CSS min-width로.
        let _ = write!(
            s,
            "<span class=\"wf-bar {cls}\" style=\"width:{pct:.2}%\"></span>",
        );
        s.push_str("</span>\n");
        let _ = writeln!(s, "<span class=\"wf-val\">{ms:.1} ms</span>");
        s.push_str("</div>\n");
    }
    let _ = writeln!(s, "<div class=\"wf-total\">total {total:.1} ms</div>");
    s.push_str("</div>\n");
}

/// leaf + 체인 인증서 표. 만료 임박/만료는 색상 강조.
fn render_cert_chain(s: &mut String, result: &ProbeResult) {
    // 최종 https hop의 체인을 우선 사용.
    let chain: &[CertInfo] = result
        .hops
        .iter()
        .rev()
        .map(|h| h.cert_chain.as_slice())
        .find(|c| !c.is_empty())
        .unwrap_or(&[]);

    if chain.is_empty() {
        return;
    }

    s.push_str("<div class=\"certs\">\n");
    s.push_str("<h3>Certificate chain</h3>\n");
    s.push_str("<table>\n<thead><tr>");
    s.push_str("<th>#</th><th>Subject</th><th>Issuer</th><th>Not after</th><th>Days left</th>");
    s.push_str("</tr></thead>\n<tbody>\n");

    for (i, cert) in chain.iter().enumerate() {
        let days_cls = if cert.days_remaining < 0 {
            "expired"
        } else if cert.days_remaining < 14 {
            "expiring"
        } else {
            "ok"
        };
        let role = if i == 0 {
            "leaf"
        } else if cert.is_ca {
            "ca"
        } else {
            "int"
        };
        s.push_str("<tr>\n");
        let _ = writeln!(s, "<td>{i} <span class=\"role\">{role}</span></td>");
        let _ = writeln!(s, "<td>{}</td>", escape(&cert.subject));
        let _ = writeln!(s, "<td>{}</td>", escape(&cert.issuer));
        let _ = writeln!(
            s,
            "<td>{}</td>",
            escape(&cert.not_after.format("%Y-%m-%d").to_string())
        );
        let _ = writeln!(s, "<td class=\"{days_cls}\">{}</td>", cert.days_remaining);
        s.push_str("</tr>\n");
    }
    s.push_str("</tbody>\n</table>\n</div>\n");
}

/// seq/timestamp/IP/status/버전/total 핵심 필드 표 + 응답 헤더.
fn render_raw_table(s: &mut String, result: &ProbeResult) {
    s.push_str("<div class=\"raw\">\n");
    s.push_str("<h3>Details</h3>\n");
    s.push_str("<table class=\"kv\">\n<tbody>\n");

    kv(s, "seq", &result.seq.to_string());
    kv(
        s,
        "timestamp",
        &result.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );

    let final_hop = result.final_hop();
    if let Some(h) = final_hop {
        kv(s, "connected IP", &h.ip.to_string());
        kv(s, "port", &h.port.to_string());
        kv(s, "status", &h.status.to_string());
        kv(s, "HTTP version", &h.http_version);
        if let Some(tls) = &h.tls {
            kv(s, "TLS", &format!("{} / {}", tls.version, tls.cipher));
            if let Some(alpn) = &tls.alpn {
                kv(s, "ALPN", alpn);
            }
        }
    }
    kv(s, "hops", &result.hops.len().to_string());
    kv(s, "total", &format!("{:.1} ms", result.total_ms));

    if !result.expect_failures.is_empty() {
        kv(s, "expect failures", &result.expect_failures.join("; "));
    }

    s.push_str("</tbody>\n</table>\n");

    // --- 응답 헤더 (최종 hop) ---
    if let Some(h) = final_hop
        && !h.response_headers.is_empty()
    {
        s.push_str("<h3>Response headers</h3>\n");
        s.push_str("<table class=\"headers\">\n<tbody>\n");
        for (k, val) in &h.response_headers {
            s.push_str("<tr>\n");
            let _ = writeln!(s, "<td class=\"hk\">{}</td>", escape(k));
            let _ = writeln!(s, "<td class=\"hv\">{}</td>", escape(val));
            s.push_str("</tr>\n");
        }
        s.push_str("</tbody>\n</table>\n");
    }

    s.push_str("</div>\n");
}

/// key/value 한 행 (값은 이스케이프).
fn kv(s: &mut String, key: &str, value: &str) {
    s.push_str("<tr>\n");
    let _ = writeln!(s, "<td class=\"k\">{}</td>", escape(key));
    let _ = writeln!(s, "<td class=\"v\">{}</td>", escape(value));
    s.push_str("</tr>\n");
}

/// HTML 이스케이프 (& < > " ' 치환). XSS/깨짐 방지.
fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// 인라인 스타일 (외부 폰트/CDN 금지, 시스템 폰트 스택만).
const STYLE: &str = r#"<style>
:root{
  --bg:#0f1117; --fg:#e6e6e6; --muted:#9aa0aa; --card:#161a23; --border:#272c38;
  --pass:#1f8b4c; --degraded:#b8860b; --down:#c0392b;
}
*{box-sizing:border-box}
body{
  margin:0; padding:1.5rem; background:var(--bg); color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px; line-height:1.5;
}
h1{font-size:1.4rem;margin:0 0 .25rem}
h2{font-size:1.1rem;margin:0 0 .75rem;word-break:break-all}
h3{font-size:.95rem;margin:1rem 0 .5rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.top{margin-bottom:1.5rem}
.meta{color:var(--muted);margin:0}
.empty{color:var(--muted);font-style:italic}
main{display:flex;flex-direction:column;gap:1.5rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem}
.banner{display:flex;align-items:center;gap:.75rem;border-radius:6px;padding:.6rem .9rem;color:#fff}
.banner.pass{background:var(--pass)}
.banner.degraded{background:var(--degraded)}
.banner.down{background:var(--down)}
.banner .state{font-weight:700;letter-spacing:.05em}
.banner .headline{font-weight:400}
.reasons{margin:.5rem 0 0;padding-left:1.25rem;color:var(--muted)}
.errbox{margin-top:.75rem;padding:.6rem .9rem;border-left:3px solid var(--down);background:rgba(192,57,43,.12);border-radius:4px}
.errbox .hint{margin-top:.4rem;color:var(--muted);font-style:italic}
.tag{display:inline-block;background:var(--down);color:#fff;border-radius:4px;padding:0 .4rem;font-size:.75rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}
.kv td.k,.headers td.hk{color:var(--muted);white-space:nowrap;width:1%}
.headers td.hv{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.role{display:inline-block;font-size:.7rem;color:var(--muted);border:1px solid var(--border);border-radius:3px;padding:0 .3rem;margin-left:.25rem}
td.ok{color:#2ecc71}
td.expiring{color:#f1c40f;font-weight:600}
td.expired{color:#e74c3c;font-weight:700}
.waterfall{margin-top:.5rem}
.wf-row{display:flex;align-items:center;gap:.5rem;margin:.2rem 0}
.wf-label{width:5rem;color:var(--muted);font-size:.8rem;flex:none}
.wf-track{flex:1;background:rgba(255,255,255,.06);border-radius:3px;height:1rem;overflow:hidden}
.wf-bar{display:block;height:100%;min-width:2px}
.wf-val{width:6rem;text-align:right;font-variant-numeric:tabular-nums;font-size:.8rem;flex:none}
.wf-total{margin-top:.4rem;color:var(--muted);font-size:.8rem}
.p-dns{background:#3498db}
.p-tcp{background:#9b59b6}
.p-tls{background:#1abc9c}
.p-ttfb{background:#e67e22}
.p-dl{background:#2ecc71}
</style>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    use crate::types::{HopResult, PhaseTimings, TlsInfo};

    #[test]
    fn escape_replaces_special_chars() {
        assert_eq!(escape("a&b"), "a&amp;b");
        assert_eq!(escape("<script>"), "&lt;script&gt;");
        assert_eq!(escape("\"x\""), "&quot;x&quot;");
        assert_eq!(escape("it's"), "it&#39;s");
        assert_eq!(escape("plain text"), "plain text");
    }

    #[test]
    fn escape_handles_combined() {
        assert_eq!(
            escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    fn sample_result() -> ProbeResult {
        let hop = HopResult {
            url: "https://example.com/".to_string(),
            ip: "93.184.216.34".parse().unwrap(),
            port: 443,
            reused_conn: false,
            local_addr: None,
            resolved_ips: vec!["93.184.216.34".parse().unwrap()],
            http_version: "HTTP/2".to_string(),
            status: 200,
            timings: PhaseTimings {
                dns_ms: Some(12.0),
                tcp_ms: 20.0,
                tls_ms: Some(40.0),
                ttfb_ms: 90.0,
                download_ms: 8.0,
                total_ms: 170.0,
            },
            tls: Some(TlsInfo {
                version: "TLSv1.3".to_string(),
                cipher: "TLS13_AES_128_GCM_SHA256".to_string(),
                alpn: Some("h2".to_string()),
                kx_group: Some("X25519".to_string()),
            }),
            cert_chain: vec![],
            response_headers: vec![("server".to_string(), "nginx".to_string())],
            body_bytes: 256,
            redirect_to: None,
        };
        ProbeResult {
            target: "https://example.com/<test>".to_string(),
            seq: 1,
            timestamp: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            hops: vec![hop],
            error: None,
            expect_failures: vec![],
            total_ms: 170.0,
        }
    }

    #[test]
    fn render_contains_doctype_and_structure() {
        let r = sample_result();
        let v = Verdict {
            state: VerdictState::Pass,
            headline: "all good".to_string(),
            reasons: vec![],
        };
        let html = render(&[r], &[v]);
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("httprove report"));
        // 배너 라벨.
        assert!(html.contains("PASS"));
        assert!(html.contains("all good"));
        // 워터폴 단계.
        assert!(html.contains("Waterfall"));
        assert!(html.contains("DNS"));
        assert!(html.contains("TTFB"));
        // raw 필드.
        assert!(html.contains("connected IP"));
        assert!(html.contains("93.184.216.34"));
        // 타깃 URL의 < > 는 이스케이프되어야 한다.
        assert!(html.contains("https://example.com/&lt;test&gt;"));
        assert!(!html.contains("https://example.com/<test>"));
    }

    #[test]
    fn render_banner_colors_by_state() {
        let r = sample_result();
        let down = Verdict {
            state: VerdictState::Down,
            headline: "unreachable".to_string(),
            reasons: vec!["connection refused".to_string()],
        };
        let html = render(&[r], &[down]);
        assert!(html.contains("banner down"));
        assert!(html.contains("DOWN"));
        assert!(html.contains("connection refused"));
    }

    #[test]
    fn empty_results_still_valid_html() {
        let html = render(&[], &[]);
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("No probe results"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn mismatched_lengths_do_not_panic() {
        let r = sample_result();
        // verdicts 비어 있음 — 배너 없이도 섹션은 렌더된다.
        let html = render(&[r], &[]);
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("Details"));
    }

    #[test]
    fn waterfall_handles_zero_timings() {
        let t = PhaseTimings {
            dns_ms: None,
            tls_ms: None,
            ..Default::default()
        };
        let mut s = String::new();
        render_waterfall(&mut s, &t);
        // tcp/ttfb/download 합이 0이면 "No timing data" 안내.
        assert!(s.contains("No timing data"));
    }
}
