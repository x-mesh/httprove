//! 설치 방식 감지 (gk internal/update/detect.go 이식).
//!
//! 실행 중인 바이너리의 절대경로(심볼릭 링크 해석 후)를 구조적으로 분석해
//! 설치 방식을 분류한다. `brew list`처럼 외부 명령에 의존하지 않는다 — 자가
//! 업데이트 도구가 PATH/셸에 의존하면 안 되기 때문.
//!
//! gk와 달리 httprove는 Rust라 go-install 분기는 없다. cargo install로 깔린
//! ~/.cargo/bin 경로도 Manual로 취급해 자가 교체를 허용한다.

use std::path::{Path, PathBuf};

/// 설치 방식.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Homebrew prefix 아래 — `brew upgrade`로 위임.
    Brew,
    /// 그 외 전부 (/usr/local/bin, ~/.local/bin, ~/.cargo/bin 등) — 자가 교체.
    Manual,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Brew => "brew",
            Source::Manual => "manual",
        }
    }
}

/// Homebrew 설치 형태 (formula vs cask). brew upgrade에 --cask 플래그가
/// 필요한지 가른다. 비-brew면 None.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrewKind {
    Formula,
    Cask,
}

/// 실행 바이너리의 해석된 설치 환경.
#[derive(Debug, Clone)]
pub struct Install {
    pub source: Source,
    /// Source::Brew일 때만 Some.
    pub brew_kind: Option<BrewKind>,
    /// 심볼릭 링크 해석된 실행 바이너리 절대경로.
    pub binary_path: PathBuf,
    /// binary_path의 부모 디렉토리 (staged 파일이 놓일 곳).
    pub dir: PathBuf,
    /// goreleaser os 명칭: "darwin" | "linux".
    pub os: &'static str,
    /// goreleaser arch 명칭: "amd64" | "arm64".
    pub arch: &'static str,
}

impl Install {
    /// 이 플랫폼의 릴리스 아카이브 파일명. `httprove_<os>_<arch>.tar.gz`.
    /// 지원하지 않는 플랫폼이면 None.
    pub fn asset_name(&self) -> Option<String> {
        if self.os.is_empty() || self.arch.is_empty() {
            return None;
        }
        Some(format!("httprove_{}_{}.tar.gz", self.os, self.arch))
    }

    /// 함께 노출할 단축 명령 이름. httprove → hpr.
    /// 바이너리 이름이 httprove[-suffix] 형태가 아니면 None (사용자가 rename한 경우).
    pub fn alias_name(&self) -> Option<String> {
        alias_for(self.binary_path.file_name()?.to_str()?)
    }
}

/// httprove 바이너리 이름 → hpr 단축 이름 (suffix 보존).
fn alias_for(bin: &str) -> Option<String> {
    if bin == "httprove" {
        return Some("hpr".to_string());
    }
    bin.strip_prefix("httprove-")
        .filter(|s| !s.is_empty())
        .map(|suffix| format!("hpr-{suffix}"))
}

/// 이 prefix들 아래에 바이너리가 있으면 Homebrew 설치로 본다.
const BREW_PREFIXES: [&str; 4] = [
    "/opt/homebrew/",
    "/usr/local/Cellar/",
    "/usr/local/Homebrew/",
    "/home/linuxbrew/.linuxbrew/",
];

/// 실행 중인 바이너리의 설치 방식을 식별한다.
pub fn detect_install() -> Result<Install, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locate running binary: {e}"))?;
    // 심볼릭 링크 해석: brew는 Cellar/Caskroom에 깔고 bin/에 심링크하므로
    // 해석하지 않으면 심링크 경로로 오분류된다. 실패 시 원본 경로 사용.
    let resolved = std::fs::canonicalize(&exe).unwrap_or(exe);

    let source = classify(&resolved);
    let brew_kind = (source == Source::Brew).then(|| classify_brew_kind(&resolved));

    Ok(Install {
        dir: resolved
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        binary_path: resolved,
        source,
        brew_kind,
        os: goreleaser_os(),
        arch: goreleaser_arch(),
    })
}

/// 절대·심링크해석된 경로의 Source 분류.
fn classify(path: &Path) -> Source {
    let s = path.to_string_lossy();
    if BREW_PREFIXES.iter().any(|p| s.starts_with(p)) {
        Source::Brew
    } else {
        Source::Manual
    }
}

/// 경로의 `/Caskroom/` vs `/Cellar/` 세그먼트로 cask/formula를 가른다.
/// 둘 다 없으면 Formula로 폴백 (과거 기본 형태이며 --cask 없는 upgrade가 더 안전).
fn classify_brew_kind(path: &Path) -> BrewKind {
    let s = path.to_string_lossy();
    if s.contains("/Caskroom/") {
        BrewKind::Cask
    } else {
        BrewKind::Formula
    }
}

/// rust 런타임 OS → goreleaser os 명칭.
fn goreleaser_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => other, // windows 등 — asset_name이 없는 플랫폼이면 상위에서 거부.
    }
}

/// rust 런타임 arch → goreleaser arch 명칭.
fn goreleaser_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_brew_paths() {
        assert_eq!(
            classify(Path::new("/opt/homebrew/bin/httprove")),
            Source::Brew
        );
        assert_eq!(
            classify(Path::new("/home/linuxbrew/.linuxbrew/bin/httprove")),
            Source::Brew
        );
        assert_eq!(
            classify(Path::new("/usr/local/Cellar/httprove/0.1.0/bin/httprove")),
            Source::Brew
        );
    }

    #[test]
    fn classify_manual_paths() {
        assert_eq!(
            classify(Path::new("/usr/local/bin/httprove")),
            Source::Manual
        );
        assert_eq!(
            classify(Path::new("/Users/me/.cargo/bin/httprove")),
            Source::Manual
        );
        assert_eq!(
            classify(Path::new("/Users/me/.local/bin/httprove")),
            Source::Manual
        );
    }

    #[test]
    fn brew_kind_cask_vs_formula() {
        assert_eq!(
            classify_brew_kind(Path::new("/opt/homebrew/Caskroom/httprove/0.1.0/httprove")),
            BrewKind::Cask
        );
        assert_eq!(
            classify_brew_kind(Path::new(
                "/opt/homebrew/Cellar/httprove/0.1.0/bin/httprove"
            )),
            BrewKind::Formula
        );
    }

    #[test]
    fn alias_preserves_suffix() {
        assert_eq!(alias_for("httprove").as_deref(), Some("hpr"));
        assert_eq!(alias_for("httprove-dev").as_deref(), Some("hpr-dev"));
        assert_eq!(alias_for("hpr"), None);
        assert_eq!(alias_for("something"), None);
    }
}
