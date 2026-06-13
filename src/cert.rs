//! X.509 인증서 체인 분석 (x509-parser 사용).
//!
//! probe.rs가 TLS 핸드셰이크에서 수집한 DER 인코딩 체인을 받아
//! 사람이 읽을 수 있는 `CertInfo`로 변환한다.
//!
//! 추출 항목:
//! - subject / issuer: RFC 2253 스타일 문자열 (`x509.subject().to_string()`)
//! - SAN: SubjectAlternativeName 확장의 DNSName / IPAddress 항목
//! - not_before / not_after: `chrono::DateTime<Utc>` (ASN1Time → unix timestamp 경유)
//! - days_remaining: 현재 시각(`Utc::now()`) 기준 만료까지 남은 일수 (음수 = 만료)
//! - serial: 대문자 16진수, 2자리마다 콜론 (예: "0A:1B:...")
//! - sig_alg: 서명 알고리즘 OID를 사람이 읽는 이름으로 (oid_registry 또는 매핑 테이블;
//!   알 수 없으면 OID 문자열 그대로)
//! - pubkey: 키 종류와 크기 요약 (예: "RSA 2048", "EC P-256", "Ed25519")
//! - is_ca: BasicConstraints 확장
//!
//! 파싱에 실패한 인증서는 결과에서 제외하지 말고, subject에
//! "<unparseable certificate>"를 넣은 항목으로 표현해 체인 길이를 보존한다.

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use x509_parser::asn1_rs::Oid;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, OID_PKCS1_MD5WITHRSAENC, OID_PKCS1_RSASSAPSS,
    OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA224WITHRSA, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SIG_ECDSA_WITH_SHA224,
    OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED448,
    OID_SIG_ED25519,
};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

use crate::types::CertInfo;

/// DER 인코딩 체인(leaf 먼저)을 CertInfo 목록으로 변환한다.
pub fn parse_cert_chain(der_chain: &[Vec<u8>]) -> Vec<CertInfo> {
    der_chain.iter().map(|der| parse_single(der)).collect()
}

/// 인증서 1장을 파싱한다. 실패 시 체인 길이 보존을 위해 placeholder를 반환한다.
fn parse_single(der: &[u8]) -> CertInfo {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => build_cert_info(&cert),
        Err(_) => unparseable_cert_info(),
    }
}

/// 파싱된 X509Certificate에서 CertInfo 필드를 추출한다.
fn build_cert_info(cert: &X509Certificate<'_>) -> CertInfo {
    let validity = cert.validity();
    let not_before = timestamp_to_datetime(validity.not_before.timestamp());
    let not_after = timestamp_to_datetime(validity.not_after.timestamp());
    let days_remaining = days_remaining_from(not_after, Utc::now());

    CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        san: extract_san(cert),
        not_before,
        not_after,
        days_remaining,
        serial: format_serial(cert.raw_serial()),
        sig_alg: sig_alg_name(&cert.signature_algorithm.algorithm),
        pubkey: pubkey_summary(cert),
        is_ca: cert.is_ca(),
    }
}

/// 만료까지 남은 일수. 음수 = 이미 만료.
///
/// floor 나눗셈(div_euclid)을 사용한다. chrono `TimeDelta::num_days()`는 0 방향으로
/// 절삭하므로 만료 후 24시간 동안 0을 반환해 "EXPIRED"가 아닌 "0 days left"로
/// 표시되는 버그가 있었다. floor면 1초라도 지난 인증서는 항상 음수가 된다.
pub fn days_remaining_from(not_after: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    const SECONDS_PER_DAY: i64 = 86_400;
    (not_after - now).num_seconds().div_euclid(SECONDS_PER_DAY)
}

/// 파싱 불가 인증서의 placeholder. 체인 길이 보존용.
fn unparseable_cert_info() -> CertInfo {
    CertInfo {
        subject: "<unparseable certificate>".to_string(),
        issuer: String::new(),
        san: Vec::new(),
        not_before: DateTime::UNIX_EPOCH,
        not_after: DateTime::UNIX_EPOCH,
        days_remaining: 0,
        serial: String::new(),
        sig_alg: String::new(),
        pubkey: String::new(),
        is_ca: false,
    }
}

/// unix timestamp(초) → DateTime<Utc>. 범위 밖이면 epoch으로 대체.
fn timestamp_to_datetime(ts: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(ts, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

/// SubjectAlternativeName 확장에서 DNS/IP 항목을 추출한다.
/// (중복 확장 등 비정상 케이스에도 동작하도록 확장 목록을 직접 순회)
fn extract_san(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut san = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(name) = ext.parsed_extension() {
            for gn in &name.general_names {
                match gn {
                    GeneralName::DNSName(dns) => san.push((*dns).to_string()),
                    GeneralName::IPAddress(bytes) => san.push(format_ip_bytes(bytes)),
                    // 그 외 항목(email, URI 등)은 TLS 진단 목적상 생략.
                    _ => {}
                }
            }
        }
    }
    san
}

/// SAN IPAddress 항목의 raw 바이트를 IP 문자열로 변환한다.
fn format_ip_bytes(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Ipv6Addr::from(octets).to_string()
        }
        // 비표준 길이는 hex로 표시.
        _ => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// 시리얼 raw 바이트 → 대문자 16진수 콜론 구분 문자열.
fn format_serial(raw: &[u8]) -> String {
    raw.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 서명 알고리즘 OID → 사람이 읽는 이름. 미등록 OID는 점 표기 문자열로 폴백.
fn sig_alg_name(oid: &Oid<'_>) -> String {
    let name = if *oid == OID_PKCS1_SHA256WITHRSA {
        "RSA-SHA256"
    } else if *oid == OID_PKCS1_SHA384WITHRSA {
        "RSA-SHA384"
    } else if *oid == OID_PKCS1_SHA512WITHRSA {
        "RSA-SHA512"
    } else if *oid == OID_PKCS1_SHA224WITHRSA {
        "RSA-SHA224"
    } else if *oid == OID_PKCS1_SHA1WITHRSA {
        "RSA-SHA1"
    } else if *oid == OID_PKCS1_MD5WITHRSAENC {
        "RSA-MD5"
    } else if *oid == OID_PKCS1_RSASSAPSS {
        "RSA-PSS"
    } else if *oid == OID_SIG_ECDSA_WITH_SHA256 {
        "ECDSA-SHA256"
    } else if *oid == OID_SIG_ECDSA_WITH_SHA384 {
        "ECDSA-SHA384"
    } else if *oid == OID_SIG_ECDSA_WITH_SHA512 {
        "ECDSA-SHA512"
    } else if *oid == OID_SIG_ECDSA_WITH_SHA224 {
        "ECDSA-SHA224"
    } else if *oid == OID_SIG_ED25519 {
        "Ed25519"
    } else if *oid == OID_SIG_ED448 {
        "Ed448"
    } else {
        return oid.to_id_string();
    };
    name.to_string()
}

/// 공개키 종류와 크기 요약 (예: "RSA 2048", "EC P-256", "Ed25519").
fn pubkey_summary(cert: &X509Certificate<'_>) -> String {
    let spki = cert.public_key();
    let alg_oid = &spki.algorithm.algorithm;

    // Ed25519/Ed448은 x509-parser의 PublicKey enum에 전용 variant가 없어
    // SPKI 알고리즘 OID로 직접 판별한다.
    if *alg_oid == OID_SIG_ED25519 {
        return "Ed25519".to_string();
    }
    if *alg_oid == OID_SIG_ED448 {
        return "Ed448".to_string();
    }

    match spki.parsed() {
        Ok(key) => match &key {
            PublicKey::RSA(_) => format!("RSA {}", key.key_size()),
            PublicKey::EC(point) => {
                // 곡선 이름은 SPKI 알고리즘 parameters의 namedCurve OID에서 추출.
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok());
                match curve {
                    Some(oid) => match curve_name(&oid) {
                        Some(name) => format!("EC {name}"),
                        None => format!("EC {}", oid.to_id_string()),
                    },
                    // parameters가 없거나 OID가 아니면 키 크기(비트)로 폴백.
                    None => format!("EC {}", point.key_size()),
                }
            }
            PublicKey::DSA(_) => format!("DSA {}", key.key_size()),
            PublicKey::GostR3410(_) | PublicKey::GostR3410_2012(_) => {
                format!("GOST {}", key.key_size())
            }
            PublicKey::Unknown(_) => alg_oid.to_id_string(),
        },
        Err(_) => alg_oid.to_id_string(),
    }
}

/// namedCurve OID → NIST 곡선 이름.
fn curve_name(oid: &Oid<'_>) -> Option<&'static str> {
    if *oid == OID_EC_P256 {
        Some("P-256")
    } else if *oid == OID_NIST_EC_P384 {
        Some("P-384")
    } else if *oid == OID_NIST_EC_P521 {
        Some("P-521")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    /// 테스트용 hex 디코더 (외부 crate 의존 없이).
    fn hex_decode(s: &str) -> Vec<u8> {
        let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(
            bytes.len().is_multiple_of(2),
            "hex string length must be even"
        );
        bytes
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
                let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// openssl로 생성한 자체 서명 EC P-256 인증서 (DER hex).
    /// CN=test.httpulse.local, SAN: DNS x2 + IP:127.0.0.1,
    /// ECDSA-SHA256 서명, CA:true, 유효기간 2026-06-12 ~ 2046-06-07.
    const EC_CERT_HEX: &str = "\
        308201cc30820171a00302010202141706253bf5ee98116cd5518c1bed5e5def69c37f30\
        0a06082a8648ce3d040302301e311c301a06035504030c13746573742e68747470756c73\
        652e6c6f63616c301e170d3236303631323136313330385a170d34363036303731363133\
        30385a301e311c301a06035504030c13746573742e68747470756c73652e6c6f63616c30\
        59301306072a8648ce3d020106082a8648ce3d03010703420004cbc900acfa5c51d71ab0\
        39a72a71ef3374f314ebb600bd17a371499ac8e21a4e0142ec93ed699c2b00294d7e15b3\
        217124d3c6bfc67c69210cc778ec926de74da3818c308189301d0603551d0e04160414c5\
        0491a3f6a93d73ed7b64274a034c1fe14ebde9301f0603551d23041830168014c50491a3\
        f6a93d73ed7b64274a034c1fe14ebde9300f0603551d130101ff040530030101ff303606\
        03551d11042f302d8213746573742e68747470756c73652e6c6f63616c82102a2e687474\
        70756c73652e6c6f63616c87047f000001300a06082a8648ce3d04030203490030460221\
        00cb8aeae42b927390ba20db4de64605c411c7de4cdcb46186829aff030a9bd3ba022100\
        b4202dc36493c306b694bd82622d5641f528aa1d564c65cd178a9773c9d641ab";

    /// openssl로 생성한 자체 서명 RSA 2048 인증서 (DER hex).
    /// CN=rsa.httpulse.local, sha256WithRSAEncryption 서명.
    const RSA_CERT_HEX: &str = "\
        3082033a30820222a00302010202146176e7dbaa75a4931757b003af85a2ffffd5a83c30\
        0d06092a864886f70d01010b0500301d311b301906035504030c127273612e6874747075\
        6c73652e6c6f63616c301e170d3236303631323136313331395a170d3436303630373136\
        313331395a301d311b301906035504030c127273612e68747470756c73652e6c6f63616c\
        30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa7959\
        e8c95480563bbfb0759a09d3c564eb6905277d13bd88ca33819a7121f7db25f06ba68732\
        507d8511908fc32f4ffce15b423d9572a2a3fa2dbdf5cf1058f39c016f778cf16064d86a\
        6c85aeebda5762f32468aea0a0f0040fe774ba9c52dc2b6fc87ca793d281d29ade42d12b\
        67348172b1583dc9f5fd25563f6ec9ad694e7a4321037adecad402551e01ff84ef798244\
        e79e075fdc4c1308844899b7de2301f8e84862beec14137944d87085d0b3f69c2af49ad1\
        3b55b2aff68899c15bc653aad00851e980c766e7a2e49668bbfd2a83785a8742cc01c810\
        7c4bc32321cf6f456490c63cbb19bf1e3f700bb3e212dc0d3c33a80ec91d9488b9132fcb\
        f30203010001a3723070301d0603551d0e041604148e412b312034271b2dec48c76af3bd\
        3a9214de69301f0603551d230418301680148e412b312034271b2dec48c76af3bd3a9214\
        de69300f0603551d130101ff040530030101ff301d0603551d110416301482127273612e\
        68747470756c73652e6c6f63616c300d06092a864886f70d01010b0500038201010005e9\
        34d86e1cc4f0d9d2c855221229aba8d4ff01f4c07ddfe158e4d57b8d1fe80fa2e7a075fa\
        a3d6532b242c5cf49db1d709c8f435df245cc25329d94d8e9835b306fed5f2788f4bdc3f\
        5e195c5afcbe0297043ec3945b6d1325a0d6f12ed60d5389a03cfddc457c0b80db2aa97a\
        260625daccf7aa1e75ca07f4cf5ca17129a229815c238dfbb3183657464d0dd3619a76a5\
        2a592963b894478c2dc5882df63c4b6cb3687bbd3359db797ea1987189387ede7077a0af\
        0a3366c316c00d5df311b043c0f8ef382ce9061db63d43cdc31cabdc2106f5686c60f6ea\
        8760a2efd3b979ace50d20ef516de5d2ab73d285fb0c4344d0ccb07c32f901915a4b4844\
        a385";

    #[test]
    fn parses_ec_certificate() {
        let der = hex_decode(EC_CERT_HEX);
        let infos = parse_cert_chain(&[der]);
        assert_eq!(infos.len(), 1);
        let info = &infos[0];

        assert_eq!(info.subject, "CN=test.httpulse.local");
        assert_eq!(info.issuer, "CN=test.httpulse.local");
        assert_eq!(
            info.san,
            vec!["test.httpulse.local", "*.httpulse.local", "127.0.0.1"]
        );
        assert_eq!(info.sig_alg, "ECDSA-SHA256");
        assert_eq!(info.pubkey, "EC P-256");
        assert!(info.is_ca);
        assert!(info.serial.starts_with("17:06:25:3B"));
        assert_eq!(info.not_before.year(), 2026);
        assert_eq!(info.not_after.year(), 2046);
        // 2046년 만료이므로 테스트 시점에서는 항상 미래.
        assert!(info.days_remaining > 0);
    }

    #[test]
    fn parses_rsa_certificate() {
        let der = hex_decode(RSA_CERT_HEX);
        let infos = parse_cert_chain(&[der]);
        assert_eq!(infos.len(), 1);
        let info = &infos[0];

        assert_eq!(info.subject, "CN=rsa.httpulse.local");
        assert_eq!(info.sig_alg, "RSA-SHA256");
        assert_eq!(info.pubkey, "RSA 2048");
        assert_eq!(info.san, vec!["rsa.httpulse.local"]);
    }

    #[test]
    fn unparseable_cert_preserves_chain_length() {
        let good = hex_decode(EC_CERT_HEX);
        let bad = vec![0x00_u8, 0x01, 0x02];
        let infos = parse_cert_chain(&[good, bad]);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].subject, "CN=test.httpulse.local");
        assert_eq!(infos[1].subject, "<unparseable certificate>");
        assert!(!infos[1].is_ca);
    }

    #[test]
    fn empty_chain_returns_empty_vec() {
        assert!(parse_cert_chain(&[]).is_empty());
    }

    #[test]
    fn format_ip_bytes_handles_v4_and_v6() {
        assert_eq!(format_ip_bytes(&[127, 0, 0, 1]), "127.0.0.1");
        let v6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ip_bytes(&v6), "::1");
        // 비표준 길이는 hex 폴백.
        assert_eq!(format_ip_bytes(&[0xAB, 0xCD]), "ab:cd");
    }

    #[test]
    fn serial_is_uppercase_colon_separated() {
        assert_eq!(format_serial(&[0x0A, 0x1B, 0xFF]), "0A:1B:FF");
    }

    #[test]
    fn days_remaining_is_negative_immediately_after_expiry() {
        let now = Utc::now();
        let hours = chrono::Duration::hours;
        // 만료 직후(<24h)도 음수여야 한다 (절삭이면 0이 되어 EXPIRED 표시를 놓침).
        assert_eq!(days_remaining_from(now - hours(12), now), -1);
        assert_eq!(
            days_remaining_from(now - chrono::Duration::seconds(1), now),
            -1
        );
        assert_eq!(days_remaining_from(now - hours(36), now), -2);
        // 아직 유효한 방향은 기존 절삭 동작과 동일하다.
        assert_eq!(days_remaining_from(now + hours(12), now), 0);
        assert_eq!(days_remaining_from(now + hours(36), now), 1);
        assert_eq!(days_remaining_from(now, now), 0);
    }
}
