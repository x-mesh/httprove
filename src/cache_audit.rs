//! CDN/캐시 효율 진단 (--cache-audit).
//!
//! 응답 헤더의 캐시 시그널(Cache-Control/Age/X-Cache/CF-Cache-Status/X-Served-By/Via 등)을
//! 파싱해 HIT/MISS·CDN·edge·age·max-age를 요약하고, 캐시를 무력화/약화하는 안티패턴
//! (Set-Cookie, no-store/private, Vary:*, max-age=0)을 짚는다. 순수 함수라 패닉 없음.

use crate::types::{CacheAudit, CacheStatus};

/// 응답 헤더로 캐시/CDN 효율을 진단한다.
pub fn audit(headers: &[(String, String)]) -> CacheAudit {
    let get = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };

    let cf_status = get("cf-cache-status");
    let x_cache = get("x-cache");
    let cache_control = get("cache-control");
    let age = get("age").and_then(|v| v.trim().parse::<u64>().ok());
    let max_age = cache_control.as_deref().and_then(parse_max_age);

    let cdn = detect_cdn(&get);

    // HIT/MISS: CF-Cache-Status 우선, 그 다음 X-Cache 문자열.
    let status = if let Some(cf) = &cf_status {
        match cf.trim().to_ascii_uppercase().as_str() {
            "HIT" => CacheStatus::Hit,
            "MISS" | "EXPIRED" | "REVALIDATED" | "UPDATING" | "STALE" => CacheStatus::Miss,
            "DYNAMIC" => CacheStatus::Dynamic,
            _ => CacheStatus::Unknown,
        }
    } else if let Some(xc) = &x_cache {
        let xc = xc.to_ascii_uppercase();
        if xc.contains("HIT") {
            CacheStatus::Hit
        } else if xc.contains("MISS") {
            CacheStatus::Miss
        } else {
            CacheStatus::Unknown
        }
    } else {
        CacheStatus::Unknown
    };

    // edge/POP: CloudFront Pop → Fastly served-by → Cloudflare ray의 데이터센터 접미.
    let edge = get("x-amz-cf-pop")
        .or_else(|| get("x-served-by"))
        .or_else(|| get("cf-ray").map(|r| r.rsplit('-').next().unwrap_or(r.as_str()).to_string()));

    let mut issues = Vec::new();
    let cc_lower = cache_control.as_deref().unwrap_or("").to_ascii_lowercase();
    if cache_control.is_none() {
        issues.push("no Cache-Control header".to_string());
    }
    if cc_lower.contains("no-store") {
        issues.push("Cache-Control: no-store — not cacheable".to_string());
    } else if cc_lower.contains("private") {
        issues.push("Cache-Control: private — not shared-cacheable".to_string());
    }
    if max_age == Some(0) {
        issues.push("max-age=0 — revalidated every request".to_string());
    }
    if get("set-cookie").is_some() && !cc_lower.contains("no-store") {
        issues.push("Set-Cookie present — may bust shared caches".to_string());
    }
    if get("vary").map(|v| v.trim() == "*").unwrap_or(false) {
        issues.push("Vary: * — uncacheable".to_string());
    }

    let summary = format!(
        "{} ({}){}{}",
        status_label(status),
        cdn.as_deref().unwrap_or("no CDN detected"),
        age.map(|a| format!(", age={a}s")).unwrap_or_default(),
        max_age
            .map(|m| format!(", max-age={m}s"))
            .unwrap_or_default(),
    );

    CacheAudit {
        status,
        cdn,
        edge,
        age,
        max_age,
        summary,
        issues,
    }
}

/// CDN 종류를 헤더 시그널로 추정한다.
fn detect_cdn(get: &impl Fn(&str) -> Option<String>) -> Option<String> {
    if get("cf-ray").is_some() || get("cf-cache-status").is_some() {
        return Some("Cloudflare".to_string());
    }
    if get("x-amz-cf-id").is_some() {
        return Some("CloudFront".to_string());
    }
    if let Some(xsb) = get("x-served-by")
        && xsb.to_ascii_lowercase().contains("cache")
    {
        return Some("Fastly".to_string());
    }
    if let Some(via) = get("via") {
        let via = via.to_ascii_lowercase();
        if via.contains("varnish") {
            return Some("Varnish".to_string());
        }
        if via.contains("cloudfront") {
            return Some("CloudFront".to_string());
        }
        if via.contains("fastly") {
            return Some("Fastly".to_string());
        }
    }
    if get("x-cache").is_some() {
        return Some("CDN (generic)".to_string());
    }
    None
}

/// Cache-Control에서 캐시 수명(초)을 뽑는다. 공유 캐시 기준이라 s-maxage를 우선한다.
fn parse_max_age(cc: &str) -> Option<u64> {
    let find = |key: &str| -> Option<u64> {
        for part in cc.split(',') {
            let part = part.trim().to_ascii_lowercase();
            if let Some(rest) = part.strip_prefix(key)
                && let Some(v) = rest.trim_start().strip_prefix('=')
            {
                return v.trim().parse().ok();
            }
        }
        None
    };
    find("s-maxage").or_else(|| find("max-age"))
}

fn status_label(s: CacheStatus) -> &'static str {
    match s {
        CacheStatus::Hit => "HIT",
        CacheStatus::Miss => "MISS",
        CacheStatus::Dynamic => "DYNAMIC",
        CacheStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn cloudflare_hit() {
        let a = audit(&h(&[
            ("cf-cache-status", "HIT"),
            ("cf-ray", "8a1b2c3d4e5f-ICN"),
            ("cache-control", "public, max-age=3600"),
            ("age", "120"),
        ]));
        assert_eq!(a.status, CacheStatus::Hit);
        assert_eq!(a.cdn.as_deref(), Some("Cloudflare"));
        assert_eq!(a.age, Some(120));
        assert_eq!(a.max_age, Some(3600));
        assert_eq!(a.edge.as_deref(), Some("ICN"));
        assert!(a.issues.is_empty());
    }

    #[test]
    fn fastly_miss_with_served_by() {
        let a = audit(&h(&[
            ("x-cache", "MISS"),
            ("x-served-by", "cache-icn1234-ICN"),
            ("cache-control", "public, s-maxage=600, max-age=60"),
        ]));
        assert_eq!(a.status, CacheStatus::Miss);
        assert_eq!(a.cdn.as_deref(), Some("Fastly"));
        assert_eq!(a.max_age, Some(600)); // s-maxage 우선
        assert_eq!(a.edge.as_deref(), Some("cache-icn1234-ICN"));
    }

    #[test]
    fn dynamic_cloudflare() {
        let a = audit(&h(&[("cf-cache-status", "DYNAMIC"), ("cf-ray", "x-ICN")]));
        assert_eq!(a.status, CacheStatus::Dynamic);
    }

    #[test]
    fn no_cache_control_and_set_cookie_flagged() {
        let a = audit(&h(&[("set-cookie", "sid=abc; Path=/")]));
        assert_eq!(a.status, CacheStatus::Unknown);
        assert!(a.cdn.is_none());
        assert!(a.issues.iter().any(|i| i.contains("no Cache-Control")));
        assert!(a.issues.iter().any(|i| i.contains("Set-Cookie")));
    }

    #[test]
    fn no_store_and_vary_star() {
        let a = audit(&h(&[
            ("cache-control", "no-store"),
            ("vary", "*"),
            ("set-cookie", "x=1"),
        ]));
        assert!(a.issues.iter().any(|i| i.contains("no-store")));
        assert!(a.issues.iter().any(|i| i.contains("Vary: *")));
        // no-store면 Set-Cookie 캐시버스트 경고는 중복이라 내지 않는다.
        assert!(!a.issues.iter().any(|i| i.contains("Set-Cookie")));
    }

    #[test]
    fn max_age_zero_flagged() {
        let a = audit(&h(&[("cache-control", "public, max-age=0")]));
        assert_eq!(a.max_age, Some(0));
        assert!(a.issues.iter().any(|i| i.contains("max-age=0")));
    }
}
