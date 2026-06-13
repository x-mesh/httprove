//! 사람이 읽는 텍스트 출력. `colored` 크레이트로 색상 처리
//! (cfg.color == false면 색상 코드 없이 — main이 `colored::control::set_override`도
//! 호출하지만, 이 모듈은 cfg.color만 보고 동작해도 된다).
//!
//! ## print_single — 단발 프로브 상세 (httpstat 스타일)
//! 출력 요소 (성공 시):
//! - 대상 줄: 최종 URL, 연결 IP:port, HTTP 버전, 상태 코드(2xx 초록/3xx 노랑/4xx,5xx 빨강)
//! - TLS 줄 (https): TLS 버전, cipher, ALPN
//! - 리다이렉트 체인이 있으면 hop 목록 (각 hop의 status → 다음 URL, hop별 total)
//! - 단계별 워터폴: 각 단계 이름 + 가로 막대(█, 최대 단계 기준 비례 폭) + ms 값.
//!   막대 시작 위치를 단계 누적 오프셋만큼 들여써서 진짜 waterfall처럼 보이게 한다.
//!   예:
//!   ```text
//!   DNS      ▕██▏              12.3 ms
//!   TCP        ▕███▏           18.1 ms
//!   TLS           ▕█████▏      33.9 ms
//!   TTFB               ▕████▏  51.2 ms
//!   Download               ▕▏   2.1 ms
//!   Total                     117.6 ms
//!   ```
//! - 인증서 블록 (https): subject CN, issuer, 유효기간(만료일 + 남은 일수),
//!   SAN 목록(5개 초과 시 "+N more"), 키/서명 알고리즘.
//!   days_remaining < 0 → 빨강 "EXPIRED", < cert_warn_days → 노랑 경고, 그 외 초록 ✓.
//!   verbose면 체인 전체(각 인증서의 subject/issuer/만료) 출력.
//! - verbose면 응답 헤더 전체 출력.
//! - 실패 시: 어느 단계(error.phase)에서 실패했는지 + 메시지, 완료된 hop이 있으면 표시.
//!
//! ## print_ping_line — ping 스타일 한 줄
//! 성공:
//!   `seq=0 93.184.216.34 200 dns=12.3ms tcp=18.1ms tls=33.9ms ttfb=51.2ms dl=2.1ms total=117.6ms`
//!   (없는 단계는 생략, 리다이렉트 시 hop 수 표시: `hops=3`)
//! - `--warn` 임계값 초과 단계 토큰은 노랑(Warn)/빨강(Crit)으로 강조 (cfg.color일 때만).
//! - 멀티 타깃(cfg.show_target)이면 줄 앞에 `[host[:port]] ` 태그.
//! - keep-alive로 연결을 재사용한 hop이면 ` conn=reused` 추가.
//! - `--expect` 위반 시 빨강 ` EXPECT-FAIL: <사유; ...>` 추가.
//!
//! 실패:
//!   `seq=1 ERROR(tls): certificate has expired` (빨강)
//!
//! ## print_summary — ping 종료 시 요약 (stderr 아님, stdout)
//! ```text
//! --- https://example.com httprove statistics ---
//! 10 probes: 9 ok, 1 failed (10.0% loss)
//! phase        min       avg       p50       p95       max    stddev
//! dns        1.2ms     2.3ms     2.1ms     4.0ms     4.2ms     0.9ms
//! ...
//! status: 200 x9
//! certificate: CN=example.com, expires 2026-09-01 (80 days left)
//! ```
//! probes 줄은 expect 위반 프로브가 있으면 `, C expect-failed`(빨강)를 추가한다.
//! last_cert가 None이면 인증서 줄 생략. 단계 샘플이 없으면(phase_stats None) 그 행 생략.

use colored::{ColoredString, Colorize};

use crate::output::OutputConfig;
use crate::stats::{Phase, StatsCollector};
use crate::types::{CertInfo, HopResult, ProbeResult, WarnLevel};

/// 워터폴 막대 영역 폭 (컬럼 수, 가장 큰 누적 오프셋+구간에 맞춰 스케일).
const BAR_WIDTH: usize = 40;
/// 워터폴 라벨 컬럼 폭 ("Download" + 여백).
const LABEL_WIDTH: usize = 9;
/// 인증서 SAN 표시 최대 개수 (초과분은 "+N more").
const SAN_DISPLAY_MAX: usize = 5;

/// cfg.color 게이트를 거쳐 색상을 적용한다. 비활성 시 원문 그대로.
fn paint(s: &str, enabled: bool, f: impl FnOnce(&str) -> ColoredString) -> String {
    if enabled {
        f(s).to_string()
    } else {
        s.to_string()
    }
}

/// `--warn` 임계값 대비 측정값 수준에 따라 토큰을 색칠한다
/// (Warn=노랑, Crit=빨강, Ok=원문). color 비활성 시 항상 원문 그대로.
fn warn_paint(s: String, value: f64, threshold: Option<f64>, color: bool) -> String {
    if !color {
        return s;
    }
    match WarnLevel::of(value, threshold) {
        WarnLevel::Ok => s,
        WarnLevel::Warn => s.as_str().yellow().to_string(),
        WarnLevel::Crit => s.as_str().red().to_string(),
    }
}

/// 멀티 타깃 표시용 host[:port] 추출. 기본 포트는 생략(url::Url이 정규화).
/// URL 파싱이 실패하거나 호스트가 없으면 타깃 문자열 전체로 폴백.
fn target_tag(target: &str) -> String {
    match url::Url::parse(target) {
        Ok(u) => match u.host_str() {
            Some(host) => match u.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            },
            None => target.to_string(),
        },
        Err(_) => target.to_string(),
    }
}

/// 상태 코드 클래스별 색상: 2xx 초록 / 3xx 노랑 / 4xx,5xx 빨강.
fn status_colored(status: u16, color: bool) -> String {
    let s = status.to_string();
    if !color {
        return s;
    }
    match status {
        200..=299 => s.as_str().green().bold().to_string(),
        300..=399 => s.as_str().yellow().to_string(),
        100..=199 => s,
        _ => s.as_str().red().bold().to_string(),
    }
}

/// 단발 프로브 상세 출력.
pub fn print_single(result: &ProbeResult, cfg: &OutputConfig) {
    if let Some(err) = &result.error {
        // 실패: 어느 단계에서 실패했는지 + 메시지.
        // 멀티 타깃 단발 모드에서는 에러 메시지에 호스트가 없을 수 있으므로
        // (예: "timed out during tls phase") 어느 타깃인지 태그로 밝힌다.
        let tag = if cfg.show_target {
            format!("[{}] ", target_tag(&result.target))
        } else {
            String::new()
        };
        let timeout_note = if err.timed_out { " (timeout)" } else { "" };
        let line = format!("{tag}ERROR({}): {}{}", err.phase, err.message, timeout_note);
        println!("{}", paint(&line, cfg.color, |s| s.red().bold()));

        // 실패 전까지 완료된 hop이 있으면 표시.
        if !result.hops.is_empty() {
            println!();
            println!("completed hops:");
            for hop in &result.hops {
                print_hop_line(hop, cfg);
            }
        }
        return;
    }

    let Some(last) = result.final_hop() else {
        // 계약상 성공이면 hop이 최소 1개지만, 방어적으로 처리.
        println!("no hops recorded");
        return;
    };

    // 대상 줄: 최종 URL, 연결 IP:port, HTTP 버전, 상태 코드.
    println!(
        "{} → {}:{}  {} {}",
        paint(&last.url, cfg.color, |s| s.bold()),
        last.ip,
        last.port,
        last.http_version,
        status_colored(last.status, cfg.color),
    );

    // TLS 줄 (https일 때만).
    if let Some(tls) = &last.tls {
        let alpn = tls.alpn.as_deref().unwrap_or("-");
        let kx = tls
            .kx_group
            .as_deref()
            .map(|g| format!("  kx={g}"))
            .unwrap_or_default();
        println!("TLS  {}  {}  ALPN={}{}", tls.version, tls.cipher, alpn, kx);
    }

    // 네트워크 줄: 로컬 소켓 → 원격, DNS 레코드가 여러 개면 나열.
    {
        let mut line = String::from("net  ");
        match last.local_addr {
            Some(local) => line.push_str(&format!("{local} → {}:{}", last.ip, last.port)),
            None => line.push_str(&format!("→ {}:{}", last.ip, last.port)),
        }
        if last.resolved_ips.len() > 1 {
            let shown: Vec<String> = last
                .resolved_ips
                .iter()
                .take(4)
                .map(ToString::to_string)
                .collect();
            let extra = last.resolved_ips.len().saturating_sub(4);
            let more = if extra > 0 {
                format!(", +{extra} more")
            } else {
                String::new()
            };
            line.push_str(&format!(
                "  (dns: {} records: {}{more})",
                last.resolved_ips.len(),
                shown.join(", "),
            ));
        }
        println!("{line}");
    }

    // 리다이렉트 체인 (hop 2개 이상).
    if result.hops.len() > 1 {
        println!();
        println!("redirects:");
        for hop in &result.hops {
            print_hop_line(hop, cfg);
        }
    }

    println!();
    print_waterfall(result, cfg);
    // keep-alive 재사용 연결: 연결 수립 단계가 생략되었음을 명시.
    if last.reused_conn {
        let note = "(connection reused — dns/tcp/tls skipped)";
        println!("{}", paint(note, cfg.color, |s| s.dimmed()));
    }

    // 응답 요약 블록 (크기/전송률 + 주요 헤더).
    println!();
    print_response_block(last);

    // --expect 위반 블록 (위반이 있을 때만 — 통과/미설정은 출력 없음).
    if !result.expect_failures.is_empty() {
        println!();
        println!("{}", paint("expect:", cfg.color, |s| s.red().bold()));
        // 색상 비활성 출력에서는 유니코드 심볼 대신 ASCII "x".
        let mark = if cfg.color { "✗" } else { "x" };
        for reason in &result.expect_failures {
            let line = format!("  {mark} {reason}");
            println!("{}", paint(&line, cfg.color, |s| s.red()));
        }
    }

    // 인증서 블록 (https hop이 하나라도 있으면).
    if let Some(leaf) = result.leaf_cert() {
        println!();
        print_cert_block(result, leaf, cfg);
    }

    // verbose: 최종 hop의 응답 헤더 전체.
    if cfg.verbose {
        println!();
        println!("response headers:");
        for (k, v) in &last.response_headers {
            println!("  {k}: {v}");
        }
    }
}

/// hop 한 줄: status, URL, (리다이렉트 시) 다음 URL, hop별 total.
fn print_hop_line(hop: &HopResult, cfg: &OutputConfig) {
    let arrow = hop
        .redirect_to
        .as_deref()
        .map(|to| format!(" → {to}"))
        .unwrap_or_default();
    println!(
        "  {} {}{}  ({:.1} ms)",
        status_colored(hop.status, cfg.color),
        hop.url,
        arrow,
        hop.timings.total_ms,
    );
}

/// 단계별 워터폴. 누적 오프셋만큼 들여쓴 █ 막대 + 오른쪽 정렬 ms 값.
/// None 타이밍 단계(dns/tls)는 행 자체를 생략한다.
/// ms 값은 `--warn` 임계값 초과 시 노랑/빨강으로 강조한다.
fn print_waterfall(result: &ProbeResult, cfg: &OutputConfig) {
    let t = result.summed_timings();
    let w = &cfg.warn;

    // (라벨, 구간 시간, 경고 임계값) — None 단계는 생략.
    let mut rows: Vec<(&str, f64, Option<f64>)> = Vec::with_capacity(5);
    if let Some(d) = t.dns_ms {
        rows.push(("DNS", d, w.dns));
    }
    rows.push(("TCP", t.tcp_ms, w.tcp));
    if let Some(d) = t.tls_ms {
        rows.push(("TLS", d, w.tls));
    }
    rows.push(("TTFB", t.ttfb_ms, w.ttfb));
    rows.push(("Download", t.download_ms, w.download));

    // 가장 큰 누적 오프셋+구간 = 표시 단계 합계 기준으로 BAR_WIDTH에 스케일.
    let phase_total: f64 = rows.iter().map(|(_, d, _)| d).sum();
    let scale = if phase_total > 0.0 {
        BAR_WIDTH as f64 / phase_total
    } else {
        0.0
    };

    let bar_field = BAR_WIDTH + 2; // ▕ ▏ 양쪽 경계 포함.
    let mut offset = 0.0_f64;
    for &(label, dur, threshold) in &rows {
        let off_cols = ((offset * scale).round() as usize).min(BAR_WIDTH);
        let blocks = (((dur * scale).round()) as usize).min(BAR_WIDTH - off_cols);
        let bar = format!("{}▕{}▏", " ".repeat(off_cols), "█".repeat(blocks));
        // 고정폭으로 먼저 포맷한 뒤 색칠해야 ANSI 코드가 컬럼 정렬을 깨지 않는다.
        let ms = warn_paint(format!("{dur:>8.1}"), dur, threshold, cfg.color);
        println!(
            "{label:<lw$}{bar:<bw$}{ms} ms",
            lw = LABEL_WIDTH,
            bw = bar_field,
        );
        offset += dur;
    }
    // Total 행은 막대 없이 같은 컬럼에 ms만 오른쪽 정렬.
    let total_ms = warn_paint(
        format!("{:>8.1}", t.total_ms),
        t.total_ms,
        w.total,
        cfg.color,
    );
    println!(
        "{:<lw$}{:<bw$}{total_ms} ms",
        "Total",
        "",
        lw = LABEL_WIDTH,
        bw = bar_field,
    );
}

/// 응답 요약 블록: 바디 크기/전송률 + 주요 응답 헤더 (있는 것만).
fn print_response_block(hop: &HopResult) {
    println!("response:");

    // 크기 + 전송률 (다운로드 시간이 의미 있을 때만 전송률 표시).
    let dl = hop.timings.download_ms;
    if hop.body_bytes > 0 && dl > 0.05 {
        let rate = hop.body_bytes as f64 / (dl / 1000.0);
        println!(
            "  size:     {} ({}/s)",
            human_bytes(hop.body_bytes),
            human_bytes(rate as u64)
        );
    } else {
        println!("  size:     {}", human_bytes(hop.body_bytes));
    }

    if let Some(server) = header_get(&hop.response_headers, "server") {
        println!("  server:   {server}");
    }
    if let Some(ctype) = header_get(&hop.response_headers, "content-type") {
        let encoding = header_get(&hop.response_headers, "content-encoding")
            .map(|e| format!(" ({e})"))
            .unwrap_or_default();
        println!("  type:     {ctype}{encoding}");
    }

    // 캐시/CDN 힌트: 존재하는 것만 모아 한 줄로.
    const CACHE_HEADERS: [&str; 7] = [
        "x-cache",
        "cf-cache-status",
        "x-cache-status",
        "x-vercel-cache",
        "via",
        "age",
        "cache-control",
    ];
    let cache_parts: Vec<String> = CACHE_HEADERS
        .iter()
        .filter_map(|name| header_get(&hop.response_headers, name).map(|v| format!("{name}: {v}")))
        .collect();
    if !cache_parts.is_empty() {
        println!("  cache:    {}", cache_parts.join(" │ "));
    }
}

/// 인증서 블록 출력. leaf 요약 + (verbose) 체인 전체.
fn print_cert_block(result: &ProbeResult, leaf: &CertInfo, cfg: &OutputConfig) {
    println!("certificate:");
    println!("  subject:  {}", leaf.subject);
    println!("  issuer:   {}", leaf.issuer);

    let not_before = leaf.not_before.format("%Y-%m-%d");
    let not_after = leaf.not_after.format("%Y-%m-%d");
    let validity = if leaf.days_remaining < 0 {
        let msg = format!(
            "{not_before} → {not_after}  (EXPIRED {} days ago)",
            -leaf.days_remaining
        );
        paint(&msg, cfg.color, |s| s.red().bold())
    } else if leaf.days_remaining < cfg.cert_warn_days {
        // 경고 심볼은 색상 활성 시에만 (no-color 출력은 텍스트만).
        let mark = if cfg.color { " ⚠" } else { "" };
        let msg = format!(
            "{not_before} → {not_after}  ({} days left{mark})",
            leaf.days_remaining
        );
        paint(&msg, cfg.color, |s| s.yellow())
    } else {
        let mark = if cfg.color { " ✓" } else { "" };
        let msg = format!(
            "{not_before} → {not_after}  ({} days left{mark})",
            leaf.days_remaining
        );
        paint(&msg, cfg.color, |s| s.green())
    };
    println!("  valid:    {validity}");

    if !leaf.san.is_empty() {
        let shown: Vec<&str> = leaf
            .san
            .iter()
            .take(SAN_DISPLAY_MAX)
            .map(String::as_str)
            .collect();
        let mut line = shown.join(", ");
        let extra = leaf.san.len().saturating_sub(SAN_DISPLAY_MAX);
        if extra > 0 {
            line.push_str(&format!(", +{extra} more"));
        }
        println!("  SAN:      {line}");
    }
    println!("  key:      {}, sig {}", leaf.pubkey, leaf.sig_alg);

    // 체인 요약 (CN만 ← 로 연결). verbose면 아래 상세 체인이 대신 나온다.
    if !cfg.verbose
        && let Some(chain_hop) = result.hops.iter().rev().find(|h| !h.cert_chain.is_empty())
        && chain_hop.cert_chain.len() > 1
    {
        let names: Vec<String> = chain_hop
            .cert_chain
            .iter()
            .map(|c| extract_cn(&c.subject))
            .collect();
        println!("  chain:    {} ({} certs)", names.join(" ← "), names.len());
    }

    // verbose: 체인 전체 (leaf가 속한 최종 https hop의 체인).
    if cfg.verbose
        && let Some(chain_hop) = result.hops.iter().rev().find(|h| !h.cert_chain.is_empty())
    {
        println!("  chain:");
        for (i, c) in chain_hop.cert_chain.iter().enumerate() {
            println!(
                "    [{}] {} — {} — expires {} ({}d{})",
                i,
                c.subject,
                c.issuer,
                c.not_after.format("%Y-%m-%d"),
                c.days_remaining,
                if c.is_ca { ", CA" } else { "" },
            );
        }
    }
}

/// ping 스타일 한 줄 출력.
pub fn print_ping_line(result: &ProbeResult, cfg: &OutputConfig) {
    // 멀티 타깃 모드: 어느 타깃의 결과인지 줄 앞에 태그로 표시.
    let tag = if cfg.show_target {
        format!("[{}] ", target_tag(&result.target))
    } else {
        String::new()
    };

    if let Some(err) = &result.error {
        let line = format!("seq={} ERROR({}): {}", result.seq, err.phase, err.message);
        println!("{tag}{}", paint(&line, cfg.color, |s| s.red()));
        return;
    }
    let Some(hop) = result.final_hop() else {
        // 계약상 도달 불가지만 방어적으로 처리.
        let line = format!("seq={} ERROR(setup): no hops recorded", result.seq);
        println!("{tag}{}", paint(&line, cfg.color, |s| s.red()));
        return;
    };

    let t = result.summed_timings();
    let w = &cfg.warn;
    let mut parts: Vec<String> = vec![
        format!("seq={}", result.seq),
        hop.ip.to_string(),
        status_colored(hop.status, cfg.color),
    ];
    if result.hops.len() > 1 {
        parts.push(format!("hops={}", result.hops.len()));
    }
    // 각 단계 토큰은 --warn 임계값 초과 시 노랑/빨강 강조.
    if let Some(d) = t.dns_ms {
        parts.push(warn_paint(format!("dns={d:.1}ms"), d, w.dns, cfg.color));
    }
    parts.push(warn_paint(
        format!("tcp={:.1}ms", t.tcp_ms),
        t.tcp_ms,
        w.tcp,
        cfg.color,
    ));
    if let Some(d) = t.tls_ms {
        parts.push(warn_paint(format!("tls={d:.1}ms"), d, w.tls, cfg.color));
    }
    parts.push(warn_paint(
        format!("ttfb={:.1}ms", t.ttfb_ms),
        t.ttfb_ms,
        w.ttfb,
        cfg.color,
    ));
    parts.push(warn_paint(
        format!("dl={:.1}ms", t.download_ms),
        t.download_ms,
        w.download,
        cfg.color,
    ));
    parts.push(warn_paint(
        format!("total={:.1}ms", result.total_ms),
        result.total_ms,
        w.total,
        cfg.color,
    ));
    // 응답 크기 (모든 hop 합) — 에러 페이지 등 크기 변화 감지용.
    let bytes: u64 = result.hops.iter().map(|h| h.body_bytes).sum();
    parts.push(format!("bytes={bytes}"));
    // keep-alive로 연결을 재사용한 hop만 표시 (새 연결 여부는 설정 없이는 구분 불가).
    if hop.reused_conn {
        parts.push(paint("conn=reused", cfg.color, |s| s.dimmed()));
    }
    // --expect 위반 사유 (빨강).
    if !result.expect_failures.is_empty() {
        let msg = format!("EXPECT-FAIL: {}", result.expect_failures.join("; "));
        parts.push(paint(&msg, cfg.color, |s| s.red()));
    }
    println!("{tag}{}", parts.join(" "));
}

/// ping 모드 종료 요약 출력. target은 표시용 URL 문자열.
pub fn print_summary(
    target: &str,
    stats: &StatsCollector,
    last_cert: Option<&CertInfo>,
    cfg: &OutputConfig,
) {
    println!("--- {target} httprove statistics ---");

    let failed_part = format!("{} failed", stats.failed());
    let failed_part = if stats.failed() > 0 {
        paint(&failed_part, cfg.color, |s| s.red())
    } else {
        failed_part
    };
    // --expect 위반 프로브가 있을 때만 expect-failed 구간 추가 (빨강).
    let expect_part = if stats.expect_failed() > 0 {
        let s = format!("{} expect-failed", stats.expect_failed());
        format!(", {}", paint(&s, cfg.color, |x| x.red()))
    } else {
        String::new()
    };
    println!(
        "{} probes: {} ok, {}{} ({:.1}% loss)",
        stats.sent(),
        stats.succeeded(),
        failed_part,
        expect_part,
        stats.loss_pct(),
    );

    // 단계별 통계 테이블 (샘플 있는 단계만, 고정폭 컬럼).
    let rows: Vec<_> = Phase::ALL
        .iter()
        .filter_map(|&p| stats.phase_stats(p).map(|s| (p, s)))
        .collect();
    if !rows.is_empty() {
        println!(
            "{:<9}{:>9}{:>9}{:>9}{:>9}{:>9}{:>9}",
            "phase", "min", "avg", "p50", "p95", "max", "stddev"
        );
        for (phase, ps) in rows {
            println!(
                "{:<9}{:>9}{:>9}{:>9}{:>9}{:>9}{:>9}",
                phase.label(),
                format!("{:.1}ms", ps.min),
                format!("{:.1}ms", ps.mean),
                format!("{:.1}ms", ps.p50),
                format!("{:.1}ms", ps.p95),
                format!("{:.1}ms", ps.max),
                format!("{:.1}ms", ps.stddev),
            );
        }
    }

    // 상태 코드 분포.
    let counts = stats.status_counts();
    if !counts.is_empty() {
        let joined = counts
            .iter()
            .map(|(code, n)| format!("{code} x{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("status: {joined}");
    }

    // 마지막으로 관측된 leaf 인증서 요약 (없으면 생략).
    if let Some(cert) = last_cert {
        let expires = cert.not_after.format("%Y-%m-%d");
        let line = if cert.days_remaining < 0 {
            paint(
                &format!(
                    "certificate: {}, expired {} ({} days ago)",
                    cert.subject, expires, -cert.days_remaining
                ),
                cfg.color,
                |s| s.red().bold(),
            )
        } else if cert.days_remaining < cfg.cert_warn_days {
            paint(
                &format!(
                    "certificate: {}, expires {} ({} days left)",
                    cert.subject, expires, cert.days_remaining
                ),
                cfg.color,
                |s| s.yellow(),
            )
        } else {
            format!(
                "certificate: {}, expires {} ({} days left)",
                cert.subject, expires, cert.days_remaining
            )
        };
        println!("{line}");
    }
}

/// 응답 헤더 목록에서 대소문자 무시로 첫 매치 값을 찾는다.
fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// 바이트 수를 사람이 읽기 좋은 단위로 (1024 기준).
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
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
