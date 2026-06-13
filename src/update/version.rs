//! semver 비교 (gk internal/update/version.go 이식).
//!
//! 태그는 "v0.1.0" 형태. 선행 'v'와 빌드/프리릴리스 suffix를 떼고
//! major.minor.patch 숫자만 비교한다. 파싱 불가한 쪽은 "더 낮음"으로 본다
//! (안전: 알 수 없으면 업데이트를 권하지 않음).

/// "v0.1.0" / "0.1.0-next" → (0, 1, 0). 실패 시 None.
fn parse(tag: &str) -> Option<(u64, u64, u64)> {
    let s = tag.trim().trim_start_matches('v').trim_start_matches('V');
    // 프리릴리스/빌드 메타데이터 제거: 첫 '-' 또는 '+' 이전까지.
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().unwrap_or("0").parse().ok()?;
    let patch = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// latest가 current보다 새 버전이면 true.
/// 어느 한쪽이라도 파싱 실패하면 false (업데이트 권하지 않음 — 보수적).
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_and_without_v() {
        assert_eq!(parse("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse("v0.1.0-next"), Some((0, 1, 0)));
        assert_eq!(parse("2"), Some((2, 0, 0)));
        assert_eq!(parse("garbage"), None);
    }

    #[test]
    fn newer_compares_numerically() {
        assert!(is_newer("v0.2.0", "v0.1.9"));
        assert!(is_newer("v0.1.10", "v0.1.9")); // 문자열 비교였다면 틀렸을 케이스.
        assert!(is_newer("v1.0.0", "v0.99.99"));
        assert!(!is_newer("v0.1.0", "v0.1.0"));
        assert!(!is_newer("v0.1.0", "v0.2.0"));
    }

    #[test]
    fn unparseable_is_not_newer() {
        assert!(!is_newer("garbage", "v0.1.0"));
        assert!(!is_newer("v0.2.0", "garbage"));
    }
}
