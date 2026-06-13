//! 정식 명령 `httprove` 진입점 (단축 명령은 src/bin/hpr.rs).

use std::process::ExitCode;

fn main() -> ExitCode {
    httprove::cli_main()
}
