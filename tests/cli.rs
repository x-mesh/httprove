use std::process::{Command, Output};

fn run(bin: &str, args: &[&str]) -> Output {
    let exe = match bin {
        "httprove" => env!("CARGO_BIN_EXE_httprove"),
        "hpr" => env!("CARGO_BIN_EXE_hpr"),
        _ => unreachable!("unknown test binary: {bin}"),
    };
    Command::new(exe)
        .args(args)
        .output()
        .expect("run test binary")
}

fn combined_output(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

#[test]
fn help_includes_core_modes() {
    let output = run("httprove", &["--help"]);
    assert!(output.status.success());

    let text = combined_output(&output);
    assert!(text.contains("--cert-check"));
    assert!(text.contains("--listen"));
    assert!(text.contains("--tui"));
    assert!(text.contains("--expect-status"));
}

#[test]
fn short_alias_reports_same_version() {
    let full = run("httprove", &["--version"]);
    let short = run("hpr", &["--version"]);

    assert!(full.status.success());
    assert!(short.status.success());
    assert_eq!(full.stdout, short.stdout);
}

#[test]
fn update_help_bypasses_probe_target_parser() {
    let output = run("httprove", &["update", "--help"]);
    assert!(output.status.success());

    let text = combined_output(&output);
    assert!(text.contains("Update httprove"));
    assert!(text.contains("--dry-run"));
    assert!(!text.contains("Target URL"));
}

#[test]
fn clap_rejects_noop_mode_combinations() {
    let output = run("httprove", &["--tui", "--json", "https://example.com"]);
    assert_eq!(output.status.code(), Some(2));

    let text = combined_output(&output);
    assert!(text.contains("cannot be used with"));
}

#[test]
fn config_validation_rejects_invalid_timing_values_before_network() {
    let output = run("httprove", &["--timeout", "0", "https://example.com"]);
    assert_eq!(output.status.code(), Some(1));

    let text = combined_output(&output);
    assert!(text.contains("--timeout must be a positive finite number"));
}
