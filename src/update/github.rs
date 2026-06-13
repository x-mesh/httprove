//! GitHub 릴리스 조회 + 에셋 URL (gk internal/update/github.go 이식).

use super::http;

/// 업스트림 `owner/repo`.
pub const REPO: &str = "x-mesh/httprove";

const DOWNLOAD_BASE: &str = "https://github.com";

/// 최신 릴리스 태그(예: "v0.1.0")를 구한다.
///
/// github.com의 `/releases/latest` 302 리다이렉트 Location을 먼저 읽는다 —
/// 이 경로는 api.github.com의 익명 60회/시간 레이트리밋을 받지 않는다
/// (install.sh가 쓰는 방법과 동일). 실패하면 api.github.com JSON으로 폴백한다.
pub async fn latest_tag() -> Result<String, String> {
    match latest_tag_redirect().await {
        Ok(tag) => Ok(tag),
        Err(redirect_err) => match latest_tag_api().await {
            Ok(tag) => Ok(tag),
            Err(api_err) => Err(format!(
                "look up latest release: redirect failed ({redirect_err}); api failed ({api_err})"
            )),
        },
    }
}

/// github.com 릴리스-latest 리다이렉트로 태그를 해석한다.
async fn latest_tag_redirect() -> Result<String, String> {
    let url = format!("{DOWNLOAD_BASE}/{REPO}/releases/latest");
    let resp = http::head_no_follow(&url).await?;
    if !(300..400).contains(&resp.status) {
        return Err(format!("expected redirect, got status {}", resp.status));
    }
    let loc = resp
        .location
        .ok_or_else(|| "redirect missing Location header".to_string())?;
    // Location: https://github.com/x-mesh/httprove/releases/tag/v0.1.0
    let tag = loc.rsplit('/').next().unwrap_or("").to_string();
    if tag.is_empty() || tag == "latest" {
        return Err(format!("unexpected redirect target {loc:?}"));
    }
    Ok(tag)
}

/// api.github.com JSON 엔드포인트 폴백 (익명, 레이트리밋 있음).
async fn latest_tag_api() -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let resp = http::get(&url, 64 * 1024).await?;
    if resp.status != 200 {
        return Err(format!("github api returned status {}", resp.status));
    }
    // serde_json으로 tag_name만 추출.
    let v: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("decode release json: {e}"))?;
    let tag = v
        .get("tag_name")
        .and_then(|t| t.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "github api returned empty tag_name".to_string())?;
    Ok(tag.to_string())
}

/// 릴리스 에셋의 직접 다운로드 URL.
/// goreleaser/install.sh/cask가 쓰는 `releases/download/<tag>/<asset>` 규칙.
pub fn asset_url(tag: &str, asset: &str) -> String {
    format!("{DOWNLOAD_BASE}/{REPO}/releases/download/{tag}/{asset}")
}
