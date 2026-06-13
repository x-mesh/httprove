//! 바이너리 원자적 교체 + 권한 상승 폴백 + 별칭 링크
//! (gk internal/update/replace.go 이식).

use std::path::Path;
use std::process::Command;

/// `staged`를 `target`으로 바꾸고, 이전 바이너리를 `target.bak`에 백업한다.
/// 두 경로는 같은 파일시스템이어야 한다 (download가 target 옆에 staged를 만들어 보장).
///
/// Linux/macOS에서 실행 중인 바이너리 교체는 안전하다: 커널이 실행 중 프로세스의
/// 옛 inode를 고정하고, 새 exec는 경로 조회로 새 파일을 찾는다. 따라서 지금 도는
/// `httprove update`는 옛 바이너리로 계속 동작하고, 다음 `httprove` 호출이 새 것을 쓴다.
pub fn atomic_replace(staged: &Path, target: &Path) -> Result<(), String> {
    if !staged.exists() {
        return Err(format!("staged binary missing: {}", staged.display()));
    }

    let bak = with_suffix(target, ".bak");
    // 중단된 이전 실행의 오래된 .bak 제거 (덮어쓰기 거부 파일시스템 대비).
    let _ = std::fs::remove_file(&bak);

    // 현재 바이너리를 클로버하기 전에 사본 보존.
    if target.exists() {
        std::fs::copy(target, &bak).map_err(|e| format!("backup current binary: {e}"))?;
    }

    std::fs::rename(staged, target)
        .map_err(|e| format!("install new binary at {}: {e}", target.display()))?;
    set_executable(target)?;
    Ok(())
}

/// `target` 디렉토리에 쓰기 권한이 없으면 `sudo install -m 0755`로 권한을 올린다
/// (대표적 /usr/local/bin 케이스). sudo가 없으면 명확한 에러를 낸다.
///
/// sudo 경로에서는 백업을 건너뛴다 — root 소유 .bak의 소유권 문제가 드물게 쓰는
/// 롤백 편의보다 크기 때문.
pub fn atomic_replace_with_sudo(staged: &Path, target: &Path) -> Result<(), String> {
    let dir = target.parent().unwrap_or(Path::new("/"));
    if writable(dir) {
        return atomic_replace(staged, target);
    }
    if which("sudo").is_none() {
        return Err(format!(
            "{} is not writable and sudo is unavailable; rerun with privileges or move {} to a user-writable location",
            dir.display(),
            target.display()
        ));
    }
    let status = Command::new("sudo")
        .arg("install")
        .arg("-m")
        .arg("0755")
        .arg(staged)
        .arg(target)
        .status()
        .map_err(|e| format!("run sudo install: {e}"))?;
    if !status.success() {
        return Err("sudo install failed".to_string());
    }
    let _ = std::fs::remove_file(staged); // install(1)이 옮겼으니 staged 정리.
    Ok(())
}

/// `dir` 안에 `alias_name` → `bin_name` 상대 심볼릭 링크를 만든다(갱신).
/// 업그레이드된 바이너리를 단축 이름(hpr)으로도 닿게 한다.
/// dir에 쓰기 권한이 없으면 sudo ln -sf로 올린다. 호출자는 실패를 치명적으로 보지
/// 않는다 — 이 시점엔 주 바이너리가 이미 자리에 있다.
pub fn link_alias(dir: &Path, bin_name: &str, alias_name: &str) -> Result<(), String> {
    let alias_path = dir.join(alias_name);
    if writable(dir) {
        // symlink는 덮어쓰기를 거부하므로 기존 별칭을 먼저 제거.
        let _ = std::fs::remove_file(&alias_path);
        #[cfg(unix)]
        {
            return std::os::unix::fs::symlink(bin_name, &alias_path)
                .map_err(|e| format!("symlink {alias_name} -> {bin_name}: {e}"));
        }
        #[cfg(not(unix))]
        {
            return Err("alias symlink is only supported on unix".to_string());
        }
    }
    if which("sudo").is_none() {
        return Err(format!(
            "{} is not writable and sudo is unavailable; cannot link {alias_name} alias",
            dir.display()
        ));
    }
    let status = Command::new("sudo")
        .arg("ln")
        .arg("-sf")
        .arg(bin_name)
        .arg(&alias_path)
        .status()
        .map_err(|e| format!("run sudo ln: {e}"))?;
    if !status.success() {
        return Err(format!("sudo ln -sf {bin_name} {}", alias_path.display()));
    }
    Ok(())
}

/// installDir에 쓸 수 있으면 그대로(이후 rename이 같은 파일시스템 유지), 아니면
/// 시스템 임시 디렉토리를 staging으로 쓴다 (이 경우 sudo install이 교차-fs 복사 처리).
pub fn pick_staging_dir(install_dir: &Path) -> std::path::PathBuf {
    if writable(install_dir) {
        install_dir.to_path_buf()
    } else {
        std::env::temp_dir()
    }
}

/// 현재 사용자가 `dir`에 파일을 만들 수 있는지 검사 (권한 비트가 아니라 실제 시도).
fn writable(dir: &Path) -> bool {
    // 고유한 프로브 파일명 생성 (Math/random 없이 pid + 단조 카운터로).
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = dir.join(format!(".httprove-probe-{}-{n}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// PATH에서 실행 파일을 찾는다 (which(1) 대체).
fn which(cmd: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// 경로에 suffix를 덧붙인다 (예: /usr/local/bin/httprove + ".bak").
fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_detects_temp_dir() {
        assert!(writable(&std::env::temp_dir()));
    }

    #[test]
    fn writable_false_for_root() {
        // /proc 같은 확실히 쓸 수 없는 경로 (있으면), 없으면 스킵.
        let ro = Path::new("/proc/nonexistent-httprove");
        if !ro.exists() {
            assert!(!writable(ro));
        }
    }

    #[test]
    fn with_suffix_appends() {
        assert_eq!(
            with_suffix(Path::new("/usr/local/bin/httprove"), ".bak"),
            Path::new("/usr/local/bin/httprove.bak")
        );
    }

    #[test]
    fn atomic_replace_swaps_and_backs_up() {
        let dir = std::env::temp_dir().join(format!("httprove-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("httprove");
        let staged = dir.join("httprove.new");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();

        atomic_replace(&staged, &target).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::read(with_suffix(&target, ".bak")).unwrap(), b"old");
        assert!(!staged.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
