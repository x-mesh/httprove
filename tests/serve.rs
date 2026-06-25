//! `httprove serve` 통합 테스트.
//!
//! 서버를 127.0.0.1:0(OS 할당 포트)로 띄우고, stderr의 "listening on …" 라인에서
//! 포트를 읽은 뒤 raw HTTP/1.1 요청(Connection: close)으로 응답을 검증한다.
//! Connection: close를 줘야 hyper가 응답 후 연결을 닫아 read_to_string이 EOF로 끝난다.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

/// 종료 시 서버 프로세스를 정리하는 가드.
struct Serve {
    child: Child,
    port: u16,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_serve(extra: &[&str]) -> Serve {
    let exe = env!("CARGO_BIN_EXE_httprove");
    let mut child = Command::new(exe)
        .arg("serve")
        .arg("127.0.0.1:0")
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");

    // 바인드는 listening 라인 출력 전에 끝나므로, 라인을 읽으면 바로 접속 가능하다.
    let stderr = child.stderr.take().expect("piped stderr");
    let mut line = String::new();
    BufReader::new(stderr)
        .read_line(&mut line)
        .expect("read listening line");
    let port = line
        .rsplit_once(':')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("could not parse port from: {line:?}"));

    Serve { child, port }
}

/// raw 요청을 보내고 (응답 헤드, 바디)를 돌려준다.
fn request(port: u16, raw: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(raw.as_bytes()).expect("write request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((resp.as_str(), ""));
    (head.to_string(), body.to_string())
}

#[test]
fn echoes_request_as_json() {
    let serve = spawn_serve(&[]);
    let (head, body) = request(
        serve.port,
        "POST /api/users?role=admin HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 14\r\n\
         Connection: close\r\n\r\n\
         {\"name\":\"jin\"}",
    );

    assert!(head.contains("200 OK"), "head: {head}");
    assert!(head.contains("application/json"), "head: {head}");
    assert!(body.contains("\"method\": \"POST\""), "body: {body}");
    assert!(body.contains("/api/users?role=admin"), "body: {body}");
    assert!(body.contains("\"role\": \"admin\""), "body: {body}");
    assert!(body.contains("jin"), "body: {body}");
}

#[test]
fn status_override_and_no_echo() {
    let serve = spawn_serve(&["--status", "503", "--no-echo"]);
    let (head, body) = request(
        serve.port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(head.contains("503"), "head: {head}");
    assert_eq!(body.trim(), "ok");
}

#[test]
fn captures_requests_for_inspection_endpoint() {
    let serve = spawn_serve(&[]);

    // 먼저 보관될 요청 하나를 보낸다.
    request(
        serve.port,
        "DELETE /widgets/42 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    // /__requests 는 dump/보관 대상이 아니며 보관 배열을 JSON으로 돌려준다.
    let (head, body) = request(
        serve.port,
        "GET /__requests HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(head.contains("200 OK"), "head: {head}");
    assert!(body.contains("\"method\": \"DELETE\""), "body: {body}");
    assert!(body.contains("/widgets/42"), "body: {body}");
}
