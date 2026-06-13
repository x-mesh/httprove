//! `httprove update` — 설치 방식 감지 기반 자가 업데이트.
//!
//! gk update를 Rust로 이식. brew 설치는 `brew upgrade`로 위임, manual 설치는
//! 릴리스 tar.gz를 받아 sha256 검증 후 원자적 교체(sudo 폴백), 단축 명령 hpr 별칭
//! 링크를 갱신한다.

mod detect;
mod download;
mod github;
mod http;
mod replace;
mod version;

use std::process::{Command, ExitCode};

use clap::Parser;

use self::detect::{BrewKind, Source};

/// `httprove update` 옵션.
#[derive(Debug, Parser)]
#[command(
    name = "httprove update",
    about = "Update httprove to the latest release",
    long_about = "Update httprove in place, matched to how it was installed.\n\n  \
        brew    → delegates to 'brew upgrade x-mesh/tap/httprove'\n  \
        manual  → downloads the matching release archive, verifies its sha256,\n            \
        and atomically replaces the running binary (sudo if the install\n            \
        dir is not writable).\n\n\
        Use --check to compare versions without downloading or updating."
)]
pub struct UpdateArgs {
    /// Only report whether a newer version exists; exit 0 if up-to-date, 1 if an update is available
    #[arg(long)]
    pub check: bool,

    /// Reinstall even if already on the latest version
    #[arg(long)]
    pub force: bool,

    /// Pin to a specific release tag (manual installs only); default is the latest release
    #[arg(long, value_name = "TAG")]
    pub to: Option<String>,

    /// Print what would happen without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

/// 현재 빌드 버전 ("0.1.0").
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `httprove update [flags]` 진입점. argv는 "update" 포함 전체.
pub fn main(argv: &[String]) -> ExitCode {
    let args = match UpdateArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            // clap이 --help/에러를 알맞은 스트림에 출력하고 종료 코드를 정한다.
            e.print().ok();
            return if e.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    run(args)
}

fn run(args: UpdateArgs) -> ExitCode {
    let install = match detect::detect_install() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("httprove update: {e}");
            return ExitCode::from(1);
        }
    };

    // --check: 다운로드/업데이트 없이 버전만 비교.
    if args.check {
        return run_check(&install);
    }

    // 대상 태그 결정: --to가 있으면 그 태그, 없으면 최신 릴리스.
    let latest = match resolve_target_tag(&args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("httprove update: {e}");
            return ExitCode::from(1);
        }
    };

    let up_to_date = !version::is_newer(&latest, CURRENT_VERSION) && args.to.is_none();
    if up_to_date && !args.force {
        println!("httprove is up to date (v{CURRENT_VERSION}).");
        return ExitCode::SUCCESS;
    }

    println!(
        "Updating httprove v{CURRENT_VERSION} → {latest}  (install: {})",
        install.source.label()
    );

    match install.source {
        Source::Brew => run_brew_upgrade(&install, args.dry_run),
        Source::Manual => run_manual_update(&install, &latest, args.dry_run),
    }
}

/// --check 처리: 최신이면 0, 새 버전이 있으면 1.
fn run_check(install: &detect::Install) -> ExitCode {
    let latest = match github_latest() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("httprove update: {e}");
            return ExitCode::from(1);
        }
    };
    let _ = install;
    if version::is_newer(&latest, CURRENT_VERSION) {
        println!("update available: v{CURRENT_VERSION} → {latest}");
        ExitCode::from(1)
    } else {
        println!("httprove is up to date (v{CURRENT_VERSION}, latest {latest}).");
        ExitCode::SUCCESS
    }
}

/// --to가 있으면 그 태그, 없으면 최신 릴리스 태그를 구한다.
fn resolve_target_tag(args: &UpdateArgs) -> Result<String, String> {
    match &args.to {
        Some(tag) => {
            // 'v' 접두사를 보정해 사용자가 "0.1.0"이라 줘도 동작.
            if tag.starts_with('v') {
                Ok(tag.clone())
            } else {
                Ok(format!("v{tag}"))
            }
        }
        None => github_latest(),
    }
}

/// 최신 릴리스 태그 조회 (async를 동기 컨텍스트에서 실행).
fn github_latest() -> Result<String, String> {
    runtime()?.block_on(github::latest_tag())
}

/// brew 설치: `brew upgrade [--cask] x-mesh/tap/httprove`로 위임.
fn run_brew_upgrade(install: &detect::Install, dry_run: bool) -> ExitCode {
    let cask = install.brew_kind == Some(BrewKind::Cask);
    let mut cmd_display = String::from("brew upgrade ");
    if cask {
        cmd_display.push_str("--cask ");
    }
    cmd_display.push_str("x-mesh/tap/httprove");

    if dry_run {
        println!("[dry-run] would run: {cmd_display}");
        return ExitCode::SUCCESS;
    }

    println!("delegating to: {cmd_display}");
    let mut cmd = Command::new("brew");
    cmd.arg("upgrade");
    if cask {
        cmd.arg("--cask");
    }
    cmd.arg("x-mesh/tap/httprove");

    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => {
            eprintln!("httprove update: brew upgrade failed");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("httprove update: run brew: {e} (is Homebrew installed?)");
            ExitCode::from(1)
        }
    }
}

/// manual 설치: 릴리스 아카이브를 받아 검증·교체하고 hpr 별칭을 링크한다.
fn run_manual_update(install: &detect::Install, tag: &str, dry_run: bool) -> ExitCode {
    let Some(asset) = install.asset_name() else {
        eprintln!(
            "httprove update: unsupported platform ({}/{}); no prebuilt archive",
            install.os, install.arch
        );
        return ExitCode::from(1);
    };

    let staging = replace::pick_staging_dir(&install.dir);

    if dry_run {
        println!("[dry-run] would download {asset} ({tag})");
        println!("[dry-run] would verify sha256 against checksums.txt");
        println!(
            "[dry-run] would replace {} (staging in {})",
            install.binary_path.display(),
            staging.display()
        );
        if let Some(alias) = install.alias_name() {
            println!(
                "[dry-run] would link alias {} -> httprove in {}",
                alias,
                install.dir.display()
            );
        }
        return ExitCode::SUCCESS;
    }

    // 다운로드 + sha256 검증 + httprove.new 추출.
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("httprove update: {e}");
            return ExitCode::from(1);
        }
    };
    println!("downloading {asset} ({tag})…");
    let staged = match rt.block_on(download::download_verified(tag, &asset, &staging)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("httprove update: {e}");
            return ExitCode::from(1);
        }
    };
    println!("verified sha256 ✓");

    // 원자적 교체 (sudo 폴백).
    if let Err(e) = replace::atomic_replace_with_sudo(&staged, &install.binary_path) {
        eprintln!("httprove update: {e}");
        let _ = std::fs::remove_file(&staged);
        return ExitCode::from(1);
    }

    // 단축 명령 hpr 별칭 링크 (실패는 비치명적 — 주 바이너리는 이미 교체됨).
    if let Some(alias) = install.alias_name()
        && let Err(e) = replace::link_alias(&install.dir, "httprove", &alias)
    {
        eprintln!("httprove update: warning: could not link {alias} alias: {e}");
    }

    println!("updated to {tag} ✓  ({})", install.binary_path.display());
    ExitCode::SUCCESS
}

/// 자가 업데이트의 네트워크 작업용 current-thread 런타임.
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("start runtime: {e}"))
}
