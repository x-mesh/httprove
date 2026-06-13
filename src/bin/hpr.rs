//! 단축 명령 `hpr` 진입점 — httprove와 완전히 동일하다.

use std::process::ExitCode;

fn main() -> ExitCode {
    httprove::cli_main()
}
