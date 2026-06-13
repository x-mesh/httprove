//! 릴리스 아카이브 다운로드 + sha256 검증 + 바이너리 추출
//! (gk internal/update/download.go 이식).

use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use sha2_min::Sha256;

use super::{github, http};

/// 아카이브 최대 크기. 릴리스 tar.gz는 ~3–10MB; 64MB로 상한.
const MAX_ARCHIVE_SIZE: usize = 64 << 20;
/// checksums.txt 상한 (수백 바이트짜리 매니페스트).
const MAX_CHECKSUMS_SIZE: usize = 64 << 10;

/// `tag`/`asset`의 릴리스 아카이브를 받아 checksums.txt로 sha256을 검증하고,
/// 아카이브 안의 `httprove` 바이너리를 `dir/httprove.new`로 추출해 그 경로를 반환한다.
///
/// `dir`은 호출자가 정한다 — 자가 업데이트에서는 실행 바이너리의 부모 디렉토리를
/// 넘겨 이후 원자적 rename이 파일시스템 경계를 넘지 않게 한다.
pub async fn download_verified(tag: &str, asset: &str, dir: &Path) -> Result<PathBuf, String> {
    let expected = fetch_expected_sum(tag, asset).await?;

    let url = github::asset_url(tag, asset);
    let resp = http::get(&url, MAX_ARCHIVE_SIZE).await?;
    if resp.status != 200 {
        return Err(format!("download {asset} returned status {}", resp.status));
    }
    let archive = resp.body;

    verify_sum(&archive, &expected)?;
    extract_binary(&archive, dir)
}

/// checksums.txt를 받아 `asset` 줄의 sha256을 꺼낸다.
/// 형식: `<sha256>  <filename>` (goreleaser/shasum 표준).
async fn fetch_expected_sum(tag: &str, asset: &str) -> Result<String, String> {
    let url = github::asset_url(tag, "checksums.txt");
    let resp = http::get(&url, MAX_CHECKSUMS_SIZE).await?;
    if resp.status != 200 {
        return Err(format!(
            "fetch checksums.txt returned status {}",
            resp.status
        ));
    }
    let text = String::from_utf8_lossy(&resp.body);
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(sum), Some(name)) = (fields.next(), fields.next()) else {
            continue;
        };
        if name == asset {
            return Ok(sum.to_lowercase());
        }
    }
    Err(format!("checksums.txt has no entry for {asset}"))
}

/// 바이트 슬라이스의 sha256을 `expected`(소문자 hex)와 비교한다.
fn verify_sum(data: &[u8], expected: &str) -> Result<(), String> {
    let actual = Sha256::digest_hex(data);
    if actual != expected.to_lowercase() {
        return Err(format!(
            "checksum mismatch (expected {expected}, got {actual})"
        ));
    }
    Ok(())
}

/// goreleaser 형태의 tar.gz에서 `httprove` 엔트리를 꺼내 `dir/httprove.new`로
/// (0755) 쓴다. 경로가 정확히 "httprove"가 아닌 엔트리는 거부한다 — 악의적 tar의
/// ../../etc/passwd 류 침투 방지.
fn extract_binary(archive: &[u8], dir: &Path) -> Result<PathBuf, String> {
    let target = dir.join("httprove.new");
    let gz = GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);

    let entries = tar
        .entries()
        .map_err(|e| format!("read tar archive: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("read tar entry: {e}"))?;
        let path = entry.path().map_err(|e| format!("tar entry path: {e}"))?;
        // 정확히 "httprove" 단일 컴포넌트만 허용.
        let is_binary = path.iter().count() == 1
            && path.file_name().and_then(|n| n.to_str()) == Some("httprove");
        if !is_binary {
            continue;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("extract httprove: {e}"))?;
        write_executable(&target, &buf)?;
        return Ok(target);
    }
    Err("archive does not contain a 'httprove' binary".to_string())
}

/// 0755 권한으로 파일을 쓴다.
fn write_executable(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

/// 의존성을 늘리지 않으려고 내부에 둔 최소 SHA-256 구현.
/// FIPS 180-4. 자가 업데이트 무결성 검증 용도로만 쓴다.
mod sha2_min {
    pub struct Sha256;

    impl Sha256 {
        /// 데이터의 SHA-256을 소문자 hex 문자열로 반환한다.
        pub fn digest_hex(data: &[u8]) -> String {
            let digest = sha256(data);
            let mut out = String::with_capacity(64);
            for b in digest {
                out.push_str(&format!("{b:02x}"));
            }
            out
        }
    }

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // 패딩.
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        let mut w = [0u32; 64];
        for chunk in msg.chunks_exact(64) {
            for (i, word) in w.iter_mut().enumerate().take(16) {
                let j = i * 4;
                *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for (hi, vi) in h.iter_mut().zip(v.iter()) {
                *hi = hi.wrapping_add(*vi);
            }
        }

        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn known_vectors() {
            // 표준 NIST 테스트 벡터.
            assert_eq!(
                Sha256::digest_hex(b""),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            assert_eq!(
                Sha256::digest_hex(b"abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            assert_eq!(
                Sha256::digest_hex(b"hello world"),
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            );
        }
    }
}
