use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;

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

#[test]
fn redirect_diagnostics_requires_follow_and_rejects_structured_output() {
    let missing_follow = run(
        "httprove",
        &["--redirect-diagnostics", "https://example.com"],
    );
    assert_eq!(missing_follow.status.code(), Some(2));
    assert!(combined_output(&missing_follow).contains("--follow"));

    let json = run(
        "httprove",
        &[
            "-L",
            "--redirect-diagnostics",
            "--json",
            "https://example.com",
        ],
    );
    assert_eq!(json.status.code(), Some(2));
    assert!(combined_output(&json).contains("cannot be used with"));
}

#[test]
fn redirect_diagnostics_reports_hop_bottlenecks_from_local_chain() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect fixture");
    let port = listener.local_addr().expect("local addr").port();
    let server = thread::spawn(move || {
        for response in [
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
        ] {
            let (mut stream, _) = listener.accept().expect("accept probe");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).expect("read request");
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let target = format!("http://127.0.0.1:{port}/start");
    let output = run(
        "httprove",
        &["-L", "--redirect-diagnostics", target.as_str()],
    );
    server.join().expect("redirect fixture thread");

    assert!(output.status.success(), "{}", combined_output(&output));
    let text = combined_output(&output);
    assert!(text.contains("redirect diagnostics:"), "{text}");
    assert!(text.contains("hop 1: status 302"), "{text}");
    assert!(text.contains("hop 2: status 200"), "{text}");
    assert!(text.contains("dominant"), "{text}");
}
