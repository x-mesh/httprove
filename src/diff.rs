//! 지문(fingerprint) 추출 + 변경 탐지, 두 프로브 JSON 간 필드 단위 diff.
//!
//! 담당 기능:
//! - ⑤ 서비스 신원 지문 + 변경 감지
//! - ⑥ run/endpoint diff 서브커맨드 (`httprove diff a.json b.json`)
//! - ⑦ since-good (저장된 마지막 정상 결과와 비교 — load_probe + diff_fingerprints 재사용)
//! - ⑧ deploy annotate helper (배포 전후 지문 변화 주석 — diff_fingerprints 재사용)
//!
//! ## fingerprint(r) -> Fingerprint
//! `r.final_hop()`에서 서비스 신원을 추출한다 (final_hop이 None이면 Default 반환):
//! - resolved_ips: final_hop.resolved_ips를 문자열로 변환 후 **정렬**.
//! - connected_ip: final_hop.ip.to_string().
//! - http_version: final_hop.http_version.
//! - status: r.status().
//! - tls_version / alpn: final_hop.tls(있으면)의 version / alpn.
//! - cert_serial / cert_spki / cert_not_after: r.leaf_cert()에서
//!   serial / spki_sha256 / not_after("%Y-%m-%d").
//! - headers: 식별성 있는 헤더만 (server, content-type 등 고정 화이트리스트, 소문자 키 비교).
//!   존재하는 것만 (key,value)로 담는다.
//!
//! ## diff_fingerprints(old, new) -> Vec<String>
//! 두 지문에서 **달라진 필드만** 사람이 읽을 한 줄로 만든다 (동일하면 빈 Vec).
//! 예:
//!   "connected_ip: 1.2.3.4 -> 5.6.7.8"
//!   "cert_serial: AA:BB -> CC:DD  (certificate rotated)"
//!   "tls_version: TLSv1.2 -> TLSv1.3"
//!   "status: 200 -> 503"
//!   "header[server]: nginx -> cloudflare"
//! cert_spki 변경은 "key pinning changed" 같은 보안적으로 의미 있는 주석을 덧붙인다.
//! headers는 양쪽을 키로 합집합 비교 — 추가/삭제/변경 모두 표기.
//!
//! ## load_probe(path) -> Result<ProbeResult>
//! 저장된 프로브 JSON(단일 객체)을 파싱한다. probe_json은 `{"type":"probe", ...}`
//! 형태이므로, serde_json::Value로 읽은 뒤 "type" 키가 있으면 무시하고 ProbeResult로
//! 역직렬화하거나, serde(deny_unknown_fields가 아니므로) 직접 from_str을 시도하되
//! 실패 시 Value 경유 폴백을 권장한다. 파일 IO/파싱 에러는 anyhow context로 감싼다.
//!
//! ## run_diff(path_a, path_b, color) -> ExitCode
//! 두 프로브 JSON을 load_probe로 읽고 **필드 단위 diff**를 출력한다:
//! status / 단계별 timings(summed_timings) / 응답 헤더 / 인증서(leaf serial·만료·spki) /
//! tls(version·cipher·alpn) / redirect 체인(redirect_to). 달라진 항목만 보여준다.
//! color면 추가/삭제/변경을 초록/빨강/노랑으로 강조(colored 크레이트).
//! 항상 정보 제공 목적이므로 **종료 코드는 0** (동일하든 다르든 0).
//! load 실패 시에만 에러 출력 후 ExitCode::from(1).
//!
//! ## 구현 메모
//! - 패닉 금지. 모든 fallible 경로는 Result/Option.
//! - fingerprint/diff_fingerprints는 순수 함수 — 네트워크 접근 없음.
//! - #[cfg(test)]로 diff_fingerprints 동일/상이 케이스를 검증하면 좋다.

use std::process::ExitCode;

use anyhow::Context;
use colored::Colorize;

use crate::types::{Fingerprint, ProbeResult};

/// 지문에 담을 식별성 있는 응답 헤더 화이트리스트 (소문자 키로 비교).
/// 서비스/인프라 신원을 드러내는 헤더만 골라 노이즈를 줄인다.
const IDENTITY_HEADERS: [&str; 8] = [
    "server",
    "content-type",
    "x-powered-by",
    "via",
    "x-served-by",
    "cf-ray",
    "x-amz-cf-id",
    "x-vercel-id",
];

/// 응답 헤더 목록에서 대소문자 무시로 첫 매치 값을 찾는다.
fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// ProbeResult의 final hop에서 서비스 신원 지문을 추출한다.
pub fn fingerprint(r: &ProbeResult) -> Fingerprint {
    // final_hop이 없으면(= 도달 실패) 빈 지문을 반환한다.
    let Some(hop) = r.final_hop() else {
        return Fingerprint::default();
    };

    // DNS가 반환한 IP들을 문자열로 변환 후 정렬 (순서 변동을 변경으로 오인하지 않게).
    let mut resolved_ips: Vec<String> = hop.resolved_ips.iter().map(ToString::to_string).collect();
    resolved_ips.sort();

    let (tls_version, alpn) = match &hop.tls {
        Some(tls) => (Some(tls.version.clone()), tls.alpn.clone()),
        None => (None, None),
    };

    // leaf 인증서(최종 https hop)에서 신원 필드 추출.
    let leaf = r.leaf_cert();
    let cert_serial = leaf.map(|c| c.serial.clone());
    let cert_spki = leaf.map(|c| c.spki_sha256.clone());
    let cert_not_after = leaf.map(|c| c.not_after.format("%Y-%m-%d").to_string());

    // 화이트리스트 순서대로, 존재하는 헤더만 (소문자 키로 정규화해 비교 안정성 확보).
    let headers: Vec<(String, String)> = IDENTITY_HEADERS
        .iter()
        .filter_map(|name| {
            header_get(&hop.response_headers, name).map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    Fingerprint {
        resolved_ips,
        connected_ip: Some(hop.ip.to_string()),
        http_version: Some(hop.http_version.clone()),
        status: r.status(),
        tls_version,
        alpn,
        cert_serial,
        cert_spki,
        cert_not_after,
        headers,
    }
}

/// Option<String> 한 쌍을 비교해 변경 시 "label: OLD -> NEW" 라인을 만든다.
/// None은 "(none)"으로 표시. 동일하면 None을 반환한다. note가 있으면 뒤에 덧붙인다.
fn diff_opt(label: &str, old: &Option<String>, new: &Option<String>, note: &str) -> Option<String> {
    if old == new {
        return None;
    }
    let o = old.as_deref().unwrap_or("(none)");
    let n = new.as_deref().unwrap_or("(none)");
    Some(format!("{label}: {o} -> {n}{note}"))
}

/// 두 지문에서 달라진 필드만 사람이 읽을 한 줄로 (동일하면 빈 Vec).
pub fn diff_fingerprints(old: &Fingerprint, new: &Fingerprint) -> Vec<String> {
    let mut lines = Vec::new();

    // resolved_ips: 정렬된 집합 차이를 +추가/-삭제 토큰으로.
    if old.resolved_ips != new.resolved_ips {
        let added: Vec<String> = new
            .resolved_ips
            .iter()
            .filter(|ip| !old.resolved_ips.contains(ip))
            .map(|ip| format!("+{ip}"))
            .collect();
        let removed: Vec<String> = old
            .resolved_ips
            .iter()
            .filter(|ip| !new.resolved_ips.contains(ip))
            .map(|ip| format!("-{ip}"))
            .collect();
        let mut tokens = added;
        tokens.extend(removed);
        // 집합은 같지만(추가/삭제 없음) 표현이 달라진 경우는 없으므로, 토큰이 있을 때만.
        if !tokens.is_empty() {
            lines.push(format!("resolved IPs: {}", tokens.join(" ")));
        }
    }

    if let Some(l) = diff_opt("connected_ip", &old.connected_ip, &new.connected_ip, "") {
        lines.push(l);
    }
    if let Some(l) = diff_opt("http_version", &old.http_version, &new.http_version, "") {
        lines.push(l);
    }
    // status는 u16 — 문자열로 변환해 동일 헬퍼 재사용.
    if old.status != new.status {
        let o = old.status.map(|s| s.to_string());
        let n = new.status.map(|s| s.to_string());
        if let Some(l) = diff_opt("status", &o, &n, "") {
            lines.push(l);
        }
    }
    if let Some(l) = diff_opt("tls_version", &old.tls_version, &new.tls_version, "") {
        lines.push(l);
    }
    if let Some(l) = diff_opt("alpn", &old.alpn, &new.alpn, "") {
        lines.push(l);
    }
    // cert_serial 변경 = 인증서 교체.
    if let Some(l) = diff_opt(
        "cert_serial",
        &old.cert_serial,
        &new.cert_serial,
        "  (certificate rotated)",
    ) {
        lines.push(l);
    }
    // cert_spki 변경 = 공개키 자체가 바뀜 → 키 핀 무효화 (보안적으로 의미 큼).
    if let Some(l) = diff_opt(
        "cert_spki",
        &old.cert_spki,
        &new.cert_spki,
        "  (key pinning changed)",
    ) {
        lines.push(l);
    }
    if let Some(l) = diff_opt(
        "cert_not_after",
        &old.cert_not_after,
        &new.cert_not_after,
        "",
    ) {
        lines.push(l);
    }

    // headers: 양쪽 키 합집합으로 추가/삭제/변경 모두 표기.
    diff_header_lines(&old.headers, &new.headers, &mut lines);

    lines
}

/// 두 헤더 목록을 키 합집합으로 비교해 변경 라인을 lines에 추가한다.
/// 화이트리스트(IDENTITY_HEADERS) 순서를 따라 결정론적으로 출력한다.
fn diff_header_lines(old: &[(String, String)], new: &[(String, String)], lines: &mut Vec<String>) {
    for &name in IDENTITY_HEADERS.iter() {
        let o = header_get(old, name);
        let n = header_get(new, name);
        match (o, n) {
            (Some(ov), Some(nv)) if ov != nv => {
                lines.push(format!("header[{name}]: {ov} -> {nv}"));
            }
            (Some(ov), None) => lines.push(format!("header[{name}]: {ov} -> (removed)")),
            (None, Some(nv)) => lines.push(format!("header[{name}]: (added) -> {nv}")),
            _ => {}
        }
    }
}

/// 저장된 프로브 JSON(단일 객체)을 ProbeResult로 파싱한다.
pub fn load_probe(path: &str) -> anyhow::Result<ProbeResult> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read probe file {path}"))?;

    // 1차: ProbeResult로 직접 역직렬화. ProbeResult는 deny_unknown_fields가 아니므로
    // {"type":"probe", ...} 의 "type" 키는 무시되어 대개 그대로 성공한다.
    if let Ok(r) = serde_json::from_str::<ProbeResult>(&data) {
        return Ok(r);
    }

    // 2차 폴백: Value로 읽어 "type" 래퍼 키를 제거한 뒤 다시 시도.
    let mut value: serde_json::Value = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse probe file {path} as JSON"))?;
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("type");
    }
    serde_json::from_value(value)
        .with_context(|| format!("failed to parse probe file {path} as ProbeResult"))
}

/// color 게이트를 거쳐 diff 라인을 색칠한다. 비활성 시 원문 그대로.
/// kind: '+' 추가(초록) / '-' 삭제(빨강) / '~' 변경(노랑).
fn paint_diff(kind: char, text: &str, color: bool) -> String {
    if !color {
        return text.to_string();
    }
    match kind {
        '+' => text.green().to_string(),
        '-' => text.red().to_string(),
        _ => text.yellow().to_string(),
    }
}

/// "A -> B" 형태의 변경 라인을 출력한다 (노랑). a==b면 아무것도 하지 않는다.
fn print_change(label: &str, a: &str, b: &str, color: bool) -> bool {
    if a == b {
        return false;
    }
    let line = format!("  {label}: {a} -> {b}");
    println!("{}", paint_diff('~', &line, color));
    true
}

/// 두 프로브 JSON을 읽어 필드 단위 diff를 출력한다 (정보 제공, exit 0).
pub fn run_diff(path_a: &str, path_b: &str, color: bool) -> ExitCode {
    let a = match load_probe(path_a) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("httprove: {e:#}");
            return ExitCode::from(1);
        }
    };
    let b = match load_probe(path_b) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("httprove: {e:#}");
            return ExitCode::from(1);
        }
    };

    println!("diff {path_a} -> {path_b}");
    let mut changed = false;

    // status (최종 hop).
    let sa = a
        .status()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "(none)".into());
    let sb = b
        .status()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "(none)".into());
    changed |= print_change("status", &sa, &sb, color);

    // 단계별 timings (모든 hop 합산). 0.1ms 미만 차이는 노이즈로 보고 무시.
    let ta = a.summed_timings();
    let tb = b.summed_timings();
    changed |= diff_timing("dns", ta.dns_ms, tb.dns_ms, color);
    changed |= diff_timing("tcp", Some(ta.tcp_ms), Some(tb.tcp_ms), color);
    changed |= diff_timing("tls", ta.tls_ms, tb.tls_ms, color);
    changed |= diff_timing("ttfb", Some(ta.ttfb_ms), Some(tb.ttfb_ms), color);
    changed |= diff_timing(
        "download",
        Some(ta.download_ms),
        Some(tb.download_ms),
        color,
    );
    changed |= diff_timing("total", Some(ta.total_ms), Some(tb.total_ms), color);

    // tls (최종 hop의 version/cipher/alpn).
    let tls_a = a.final_hop().and_then(|h| h.tls.as_ref());
    let tls_b = b.final_hop().and_then(|h| h.tls.as_ref());
    changed |= print_change(
        "tls.version",
        tls_a.map(|t| t.version.as_str()).unwrap_or("(none)"),
        tls_b.map(|t| t.version.as_str()).unwrap_or("(none)"),
        color,
    );
    changed |= print_change(
        "tls.cipher",
        tls_a.map(|t| t.cipher.as_str()).unwrap_or("(none)"),
        tls_b.map(|t| t.cipher.as_str()).unwrap_or("(none)"),
        color,
    );
    changed |= print_change(
        "tls.alpn",
        tls_a.and_then(|t| t.alpn.as_deref()).unwrap_or("(none)"),
        tls_b.and_then(|t| t.alpn.as_deref()).unwrap_or("(none)"),
        color,
    );

    // 인증서 (leaf serial / 만료 / spki).
    let ca = a.leaf_cert();
    let cb = b.leaf_cert();
    changed |= print_change(
        "cert.serial",
        ca.map(|c| c.serial.as_str()).unwrap_or("(none)"),
        cb.map(|c| c.serial.as_str()).unwrap_or("(none)"),
        color,
    );
    changed |= print_change(
        "cert.not_after",
        &ca.map(|c| c.not_after.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "(none)".into()),
        &cb.map(|c| c.not_after.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "(none)".into()),
        color,
    );
    changed |= print_change(
        "cert.spki",
        ca.map(|c| c.spki_sha256.as_str()).unwrap_or("(none)"),
        cb.map(|c| c.spki_sha256.as_str()).unwrap_or("(none)"),
        color,
    );

    // 응답 헤더 (최종 hop) — 키 합집합으로 추가/삭제/변경.
    let ha: &[(String, String)] = a
        .final_hop()
        .map(|h| h.response_headers.as_slice())
        .unwrap_or(&[]);
    let hb: &[(String, String)] = b
        .final_hop()
        .map(|h| h.response_headers.as_slice())
        .unwrap_or(&[]);
    changed |= diff_response_headers(ha, hb, color);

    // redirect 체인 (각 hop의 redirect_to 순서대로).
    let ra: Vec<String> = a
        .hops
        .iter()
        .filter_map(|h| h.redirect_to.clone())
        .collect();
    let rb: Vec<String> = b
        .hops
        .iter()
        .filter_map(|h| h.redirect_to.clone())
        .collect();
    if ra != rb {
        changed = true;
        let from = if ra.is_empty() {
            "(none)".to_string()
        } else {
            ra.join(" -> ")
        };
        let to = if rb.is_empty() {
            "(none)".to_string()
        } else {
            rb.join(" -> ")
        };
        let line = format!("  redirects: {from}  ==>  {to}");
        println!("{}", paint_diff('~', &line, color));
    }

    if !changed {
        println!("  (no differences)");
    }
    // 정보 제공 목적 — 동일/상이 무관하게 항상 성공 종료.
    ExitCode::SUCCESS
}

/// 단계 timing 한 쌍을 비교해 0.1ms 이상 차이가 나면 변경 라인을 출력한다.
/// None(단계 없음)은 "-"로 표시. 둘 다 None이거나 차이가 미미하면 출력 안 함.
fn diff_timing(label: &str, a: Option<f64>, b: Option<f64>, color: bool) -> bool {
    let same = match (a, b) {
        (Some(x), Some(y)) => (x - y).abs() < 0.1,
        (None, None) => true,
        _ => false,
    };
    if same {
        return false;
    }
    let fmt = |v: Option<f64>| v.map(|x| format!("{x:.1}ms")).unwrap_or_else(|| "-".into());
    let line = format!("  {label}: {} -> {}", fmt(a), fmt(b));
    println!("{}", paint_diff('~', &line, color));
    true
}

/// 두 응답 헤더 목록을 키 합집합으로 비교해 추가/삭제/변경 라인을 출력한다.
/// 출력 순서 안정성을 위해 키를 정렬한다. 키는 소문자로 정규화해 비교한다.
fn diff_response_headers(old: &[(String, String)], new: &[(String, String)], color: bool) -> bool {
    // 양쪽의 소문자 키 합집합을 정렬.
    let mut keys: Vec<String> = old
        .iter()
        .chain(new.iter())
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    keys.sort();
    keys.dedup();

    let mut changed = false;
    for key in keys {
        let o = header_get(old, &key);
        let n = header_get(new, &key);
        match (o, n) {
            (Some(ov), Some(nv)) if ov != nv => {
                changed = true;
                let line = format!("  header[{key}]: {ov} -> {nv}");
                println!("{}", paint_diff('~', &line, color));
            }
            (Some(ov), None) => {
                changed = true;
                let line = format!("  header[{key}]: {ov} (removed)");
                println!("{}", paint_diff('-', &line, color));
            }
            (None, Some(nv)) => {
                changed = true;
                let line = format!("  header[{key}]: {nv} (added)");
                println!("{}", paint_diff('+', &line, color));
            }
            _ => {}
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    use crate::types::{CertInfo, HopResult, PhaseTimings, ProbeResult, TlsInfo};

    /// 테스트용 leaf 인증서 1개 만들기. not_after는 "YYYY-MM-DD".
    fn cert(serial: &str, spki: &str, not_after: &str) -> CertInfo {
        let na = chrono::NaiveDate::parse_from_str(not_after, "%Y-%m-%d")
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        CertInfo {
            subject: "CN=example.com".into(),
            issuer: "CN=Test CA".into(),
            san: vec!["example.com".into()],
            not_before: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            not_after: na,
            days_remaining: 90,
            serial: serial.to_string(),
            sig_alg: "ECDSA-SHA256".into(),
            pubkey: "EC P-256".into(),
            is_ca: false,
            spki_sha256: spki.to_string(),
            aia_ca_issuers: None,
        }
    }

    /// 테스트용 ProbeResult — hop 1개 (https, leaf cert 포함).
    fn probe(
        ip: &str,
        status: u16,
        tls_version: &str,
        alpn: Option<&str>,
        leaf: Option<CertInfo>,
        headers: Vec<(&str, &str)>,
        resolved: Vec<&str>,
    ) -> ProbeResult {
        let hop = HopResult {
            url: "https://example.com/".into(),
            ip: ip.parse().unwrap(),
            port: 443,
            reused_conn: false,
            local_addr: None,
            resolved_ips: resolved.iter().map(|s| s.parse().unwrap()).collect(),
            http_version: "HTTP/2".into(),
            status,
            timings: PhaseTimings {
                dns_ms: Some(5.0),
                tcp_ms: 10.0,
                tls_ms: Some(20.0),
                ttfb_ms: 30.0,
                download_ms: 2.0,
                total_ms: 67.0,
            },
            tls: Some(TlsInfo {
                version: tls_version.into(),
                cipher: "TLS13_AES_128_GCM_SHA256".into(),
                alpn: alpn.map(String::from),
                kx_group: Some("X25519".into()),
            }),
            cert_chain: leaf.into_iter().collect(),
            response_headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body_bytes: 1234,
            redirect_to: None,
        };
        ProbeResult {
            target: "https://example.com".into(),
            seq: 0,
            timestamp: Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
            hops: vec![hop],
            error: None,
            expect_failures: vec![],
            total_ms: 67.0,
        }
    }

    /// 기준 프로브 (변경 비교의 "old" 쪽).
    fn base_probe() -> ProbeResult {
        probe(
            "1.2.3.4",
            200,
            "TLSv1.3",
            Some("h2"),
            Some(cert("AA:BB", "spki-old", "2026-09-01")),
            vec![("server", "nginx"), ("content-type", "text/html")],
            vec!["1.2.3.4", "5.6.7.8"],
        )
    }

    #[test]
    fn identical_fingerprints_yield_no_diff() {
        let r = base_probe();
        let fp = fingerprint(&r);
        // 동일 입력 → 지문 동일 → 빈 델타.
        assert!(diff_fingerprints(&fp, &fp).is_empty());
    }

    #[test]
    fn fingerprint_pulls_identity_fields() {
        let fp = fingerprint(&base_probe());
        assert_eq!(fp.connected_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(fp.status, Some(200));
        assert_eq!(fp.tls_version.as_deref(), Some("TLSv1.3"));
        assert_eq!(fp.alpn.as_deref(), Some("h2"));
        assert_eq!(fp.cert_serial.as_deref(), Some("AA:BB"));
        assert_eq!(fp.cert_spki.as_deref(), Some("spki-old"));
        assert_eq!(fp.cert_not_after.as_deref(), Some("2026-09-01"));
        // resolved_ips는 정렬되어 있어야 한다.
        assert_eq!(fp.resolved_ips, vec!["1.2.3.4", "5.6.7.8"]);
        // 화이트리스트 헤더만 (server, content-type).
        assert_eq!(fp.headers.len(), 2);
    }

    #[test]
    fn fingerprint_empty_when_no_hops() {
        let mut r = base_probe();
        r.hops.clear();
        let fp = fingerprint(&r);
        assert!(fp.connected_ip.is_none());
        assert!(fp.status.is_none());
        assert!(fp.resolved_ips.is_empty());
    }

    #[test]
    fn diff_connected_ip_change() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        p.hops[0].ip = "9.9.9.9".parse().unwrap();
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        assert!(d.iter().any(|l| l == "connected_ip: 1.2.3.4 -> 9.9.9.9"));
    }

    #[test]
    fn diff_status_change() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        p.hops[0].status = 503;
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        assert!(d.iter().any(|l| l == "status: 200 -> 503"));
    }

    #[test]
    fn diff_tls_version_change() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        if let Some(tls) = p.hops[0].tls.as_mut() {
            tls.version = "TLSv1.2".into();
        }
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        assert!(d.iter().any(|l| l == "tls_version: TLSv1.3 -> TLSv1.2"));
    }

    #[test]
    fn diff_cert_serial_change_notes_rotation() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        p.hops[0].cert_chain[0].serial = "CC:DD".into();
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        assert!(
            d.iter()
                .any(|l| l == "cert_serial: AA:BB -> CC:DD  (certificate rotated)"),
            "got: {d:?}"
        );
    }

    #[test]
    fn diff_cert_spki_change_notes_pinning() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        p.hops[0].cert_chain[0].spki_sha256 = "spki-new".into();
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        assert!(
            d.iter()
                .any(|l| l == "cert_spki: spki-old -> spki-new  (key pinning changed)"),
            "got: {d:?}"
        );
    }

    #[test]
    fn diff_resolved_ips_add_and_remove() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        // 5.6.7.8 제거, 7.7.7.7 추가.
        p.hops[0].resolved_ips = vec!["1.2.3.4".parse().unwrap(), "7.7.7.7".parse().unwrap()];
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        let line = d
            .iter()
            .find(|l| l.starts_with("resolved IPs:"))
            .expect("resolved IPs line present");
        assert!(line.contains("+7.7.7.7"), "got: {line}");
        assert!(line.contains("-5.6.7.8"), "got: {line}");
    }

    #[test]
    fn diff_header_add_remove_change() {
        let old = fingerprint(&base_probe());
        let mut p = base_probe();
        // server 변경, content-type 제거, via 추가.
        p.hops[0].response_headers = vec![
            ("server".into(), "cloudflare".into()),
            ("via".into(), "1.1 varnish".into()),
        ];
        let new = fingerprint(&p);
        let d = diff_fingerprints(&old, &new);
        assert!(d.iter().any(|l| l == "header[server]: nginx -> cloudflare"));
        assert!(
            d.iter()
                .any(|l| l == "header[content-type]: text/html -> (removed)")
        );
        assert!(d.iter().any(|l| l == "header[via]: (added) -> 1.1 varnish"));
    }

    #[test]
    fn load_probe_round_trip() {
        // probe_json이 만드는 {"type":"probe", ...} 형태를 그대로 파싱할 수 있어야 한다.
        let r = base_probe();
        let json = crate::output::json::probe_json(&r);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("httprove_diff_rt_{}.json", std::process::id()));
        let path_str = path.to_string_lossy().to_string();
        std::fs::write(&path, &json).expect("write temp probe json");

        let loaded = load_probe(&path_str).expect("load_probe round trip");
        // 핵심 필드 보존 확인.
        assert_eq!(loaded.target, r.target);
        assert_eq!(loaded.status(), Some(200));
        assert_eq!(loaded.leaf_cert().map(|c| c.serial.as_str()), Some("AA:BB"));
        // 왕복한 지문이 원본 지문과 동일해야 한다 (델타 없음).
        assert!(diff_fingerprints(&fingerprint(&r), &fingerprint(&loaded)).is_empty());

        let _ = std::fs::remove_file(&path);
    }
}
