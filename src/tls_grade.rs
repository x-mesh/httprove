//! TLS 연결 보안 스코어카드 (--tls-grade).
//!
//! 협상된 `TlsInfo`(version/cipher/kx) + 응답 헤더(HSTS) + 체인 분석(`ChainAnalysis`)을
//! 종합해 A~F 등급을 낸다. rustls 클라이언트는 안전한 AEAD+FS cipher만 협상하므로 cipher
//! 자체는 대개 만점이지만, protocol 다운그레이드(TLS 1.2), 약한 key exchange, HSTS 부재,
//! 인증서 체인 문제(불완전/만료 임박)를 한 화면에서 잡아낸다.
//!
//! testssl처럼 서버가 지원하는 *모든* cipher를 전수 스캔하지는 않는다 — 이 등급은 **실제
//! 협상된 이 연결**의 구성 품질이다. 순수 함수라 패닉 없음.

use crate::types::{ChainAnalysis, TlsGrade, TlsInfo};

/// HSTS 권장 최소 max-age (180일). 이보다 짧으면 약한 감점.
const HSTS_MIN_MAX_AGE: u64 = 180 * 24 * 60 * 60;

/// 협상된 TLS 구성 + HSTS + 체인을 A~F로 등급화한다.
pub fn grade(tls: &TlsInfo, headers: &[(String, String)], chain: &ChainAnalysis) -> TlsGrade {
    let mut score: i32 = 100;
    let mut deductions = Vec::new();

    // --- protocol version: 1.3 만점, 1.2 경미 감점, 그 이하 큰 감점 ---
    match tls.version.as_str() {
        "TLSv1.3" => {}
        "TLSv1.2" => {
            score -= 10;
            deductions.push("TLS 1.2 negotiated (not 1.3): -10".to_string());
        }
        other => {
            score -= 40;
            deductions.push(format!("obsolete protocol {other}: -40"));
        }
    }

    // --- cipher: forward secrecy + AEAD (cipher 문자열로 판별) ---
    let c = tls.cipher.to_ascii_uppercase();
    let fs = c.starts_with("TLS13") || c.contains("ECDHE") || c.contains("DHE");
    let aead =
        c.contains("GCM") || c.contains("CHACHA20") || c.contains("POLY1305") || c.contains("CCM");
    if !fs {
        score -= 30;
        deductions.push(format!("no forward secrecy ({}): -30", tls.cipher));
    }
    if !aead {
        score -= 20;
        deductions.push(format!("non-AEAD cipher ({}): -20", tls.cipher));
    }

    // --- key exchange group: 알 수 없으면(None) 정보 부족이므로 감점하지 않는다 ---
    let kx_strong = match tls.kx_group.as_deref() {
        Some(g) => {
            let g = g.to_ascii_uppercase();
            g.contains("X25519")
                || g.contains("SECP256")
                || g.contains("SECP384")
                || g.contains("SECP521")
                || g.contains("MLKEM")
        }
        None => true,
    };
    if !kx_strong {
        score -= 15;
        deductions.push(format!(
            "weak key exchange ({}): -15",
            tls.kx_group.as_deref().unwrap_or("?")
        ));
    }

    // --- HSTS: 부재/약한 max-age 감점 ---
    let hsts_desc = match find_header(headers, "strict-transport-security") {
        None => {
            score -= 10;
            deductions.push("no HSTS header: -10".to_string());
            "no HSTS".to_string()
        }
        Some(v) => match parse_hsts_max_age(&v) {
            Some(age) if age >= HSTS_MIN_MAX_AGE => format!("HSTS {}", humanize_age(age)),
            Some(age) => {
                score -= 5;
                deductions.push(format!("HSTS max-age {} < 180d: -5", humanize_age(age)));
                format!("HSTS {}", humanize_age(age))
            }
            None => {
                score -= 5;
                deductions.push("HSTS header without max-age: -5".to_string());
                "HSTS (no max-age)".to_string()
            }
        },
    };

    // --- cert chain (chain::analyze 결과 재사용) ---
    if chain.incomplete {
        score -= 10;
        deductions.push("incomplete cert chain (intermediate missing): -10".to_string());
    }
    if chain.weakest_days < 0 {
        score -= 40;
        deductions.push(format!(
            "certificate expired ({}d ago): -40",
            chain.weakest_days.abs()
        ));
    } else if chain.weakest_days < 14 {
        score -= 10;
        deductions.push(format!(
            "cert chain expires in {}d (<14): -10",
            chain.weakest_days
        ));
    }

    score = score.max(0);
    let summary = format!(
        "{}, {}, {}, {}, chain {}",
        tls.version,
        tls.kx_group.as_deref().unwrap_or("?"),
        if aead { "AEAD" } else { "non-AEAD" },
        hsts_desc,
        if chain.incomplete { "incomplete" } else { "OK" }
    );

    TlsGrade {
        letter: letter_for(score),
        score,
        summary,
        deductions,
    }
}

/// 점수 → 등급 글자.
fn letter_for(score: i32) -> char {
    match score {
        90.. => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        50..=59 => 'E',
        _ => 'F',
    }
}

/// 헤더 이름(대소문자 무시)으로 첫 값을 찾는다.
fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Strict-Transport-Security 헤더에서 `max-age=<n>`(초)을 추출한다. 디렉티브는 대소문자 무시.
fn parse_hsts_max_age(value: &str) -> Option<u64> {
    for part in value.split(';') {
        let part = part.trim().to_ascii_lowercase();
        if let Some(rest) = part.strip_prefix("max-age") {
            let rest = rest
                .trim_start()
                .strip_prefix('=')?
                .trim()
                .trim_matches('"');
            return rest.parse::<u64>().ok();
        }
    }
    None
}

/// 초를 사람이 읽을 근사치로 (예: 31536000 → "1y", 86400 → "1d").
fn humanize_age(secs: u64) -> String {
    let days = secs / 86_400;
    if days >= 365 {
        format!("{}y", days / 365)
    } else if days >= 1 {
        format!("{days}d")
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(version: &str, cipher: &str, kx: Option<&str>) -> TlsInfo {
        TlsInfo {
            version: version.to_string(),
            cipher: cipher.to_string(),
            alpn: Some("h2".to_string()),
            kx_group: kx.map(str::to_string),
        }
    }

    fn chain(incomplete: bool, weakest_days: i64) -> ChainAnalysis {
        ChainAnalysis {
            incomplete,
            aia_repairable: None,
            weakest_days,
            weakest_subject: "CN=example.com".to_string(),
            issues: vec![],
        }
    }

    fn hsts(v: &str) -> Vec<(String, String)> {
        vec![("strict-transport-security".to_string(), v.to_string())]
    }

    #[test]
    fn tls13_x25519_hsts_chain_ok_is_a() {
        let g = grade(
            &tls("TLSv1.3", "TLS13_AES_128_GCM_SHA256", Some("X25519")),
            &hsts("max-age=31536000; includeSubDomains"),
            &chain(false, 80),
        );
        assert_eq!(g.letter, 'A', "deductions: {:?}", g.deductions);
        assert_eq!(g.score, 100);
        assert!(g.deductions.is_empty());
    }

    #[test]
    fn tls12_costs_ten_points() {
        let g = grade(
            &tls(
                "TLSv1.2",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                Some("X25519"),
            ),
            &hsts("max-age=31536000"),
            &chain(false, 80),
        );
        assert_eq!(g.score, 90);
        assert_eq!(g.letter, 'A'); // 90 still A
        assert!(g.deductions.iter().any(|d| d.contains("TLS 1.2")));
    }

    #[test]
    fn missing_hsts_is_deducted() {
        let g = grade(
            &tls("TLSv1.3", "TLS13_AES_128_GCM_SHA256", Some("X25519")),
            &[],
            &chain(false, 80),
        );
        assert_eq!(g.score, 90);
        assert!(g.deductions.iter().any(|d| d.contains("no HSTS")));
    }

    #[test]
    fn expired_cert_tanks_grade() {
        let g = grade(
            &tls("TLSv1.3", "TLS13_AES_128_GCM_SHA256", Some("X25519")),
            &hsts("max-age=31536000"),
            &chain(false, -3),
        );
        // 100 - 40(expired) = 60 → D
        assert_eq!(g.score, 60);
        assert_eq!(g.letter, 'D');
        assert!(g.deductions.iter().any(|d| d.contains("expired")));
    }

    #[test]
    fn incomplete_chain_and_near_expiry_stack() {
        let g = grade(
            &tls("TLSv1.3", "TLS13_AES_128_GCM_SHA256", Some("X25519")),
            &hsts("max-age=31536000"),
            &chain(true, 5),
        );
        // 100 - 10(incomplete) - 10(<14d) = 80 → B
        assert_eq!(g.score, 80);
        assert_eq!(g.letter, 'B');
    }

    #[test]
    fn parse_hsts_max_age_variants() {
        assert_eq!(
            parse_hsts_max_age("max-age=31536000; includeSubDomains"),
            Some(31_536_000)
        );
        assert_eq!(
            parse_hsts_max_age("includeSubDomains; Max-Age=300"),
            Some(300)
        );
        assert_eq!(parse_hsts_max_age("includeSubDomains"), None);
        assert_eq!(parse_hsts_max_age("max-age=\"600\""), Some(600));
    }

    #[test]
    fn weak_kx_deducted_but_none_is_not() {
        let weak = grade(
            &tls("TLSv1.3", "TLS13_AES_128_GCM_SHA256", Some("secp192r1")),
            &hsts("max-age=31536000"),
            &chain(false, 80),
        );
        assert!(
            weak.deductions
                .iter()
                .any(|d| d.contains("weak key exchange"))
        );
        let unknown = grade(
            &tls("TLSv1.3", "TLS13_AES_128_GCM_SHA256", None),
            &hsts("max-age=31536000"),
            &chain(false, 80),
        );
        assert_eq!(unknown.score, 100); // None kx는 감점 없음
    }
}
