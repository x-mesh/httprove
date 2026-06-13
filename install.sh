#!/usr/bin/env sh
# httprove 설치 스크립트 — 최신 릴리스 바이너리를 내려받아 설치한다.
#
#   curl -fsSL https://raw.githubusercontent.com/x-mesh/httprove/main/install.sh | sh
#
# 동작:
#   - OS/아키텍처를 감지해 httprove_<os>_<arch>.tar.gz 를 받는다.
#   - checksums.txt 의 sha256 으로 무결성을 검증한다.
#   - 쓰기 가능한 bin 디렉토리(~/.local/bin → /usr/local/bin 순)에 설치한다.
#   - 단축 명령 hpr 심볼릭 링크를 만든다.
#
# 환경변수:
#   HTTPROVE_INSTALL_DIR  설치 디렉토리 강제 지정
#   HTTPROVE_VERSION      특정 태그 설치 (기본: 최신)
set -eu

REPO="x-mesh/httprove"
BIN="httprove"
ALIAS="hpr"

info() { printf '\033[36m==>\033[0m %s\n' "$1" >&2; }
err()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- 플랫폼 감지 --------------------------------------------------------------
os=$(uname -s)
case "$os" in
  Darwin) goos=darwin ;;
  Linux)  goos=linux ;;
  *) err "unsupported OS: $os (only macOS and Linux)" ;;
esac

arch=$(uname -m)
case "$arch" in
  arm64|aarch64) goarch=arm64 ;;
  x86_64|amd64)  goarch=amd64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

asset="${BIN}_${goos}_${goarch}.tar.gz"

# --- 도구 확인 ----------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
have curl || have wget || err "curl or wget is required"
have tar || err "tar is required"

fetch() { # fetch <url> <out>
  if have curl; then curl -fsSL "$1" -o "$2"
  else wget -qO "$2" "$1"; fi
}
fetch_stdout() { # fetch_stdout <url>
  if have curl; then curl -fsSL "$1"
  else wget -qO- "$1"; fi
}

# --- 버전 결정 ----------------------------------------------------------------
tag="${HTTPROVE_VERSION:-}"
if [ -z "$tag" ]; then
  info "resolving latest release"
  # /releases/latest 는 /releases/tag/<tag> 로 302. Location 의 basename 이 태그.
  loc=$(
    if have curl; then curl -fsSLI -o /dev/null -w '%{url_effective}' \
      "https://github.com/${REPO}/releases/latest"
    else wget -qS --max-redirect=5 -O /dev/null \
      "https://github.com/${REPO}/releases/latest" 2>&1 | awk '/Location:/{print $2}' | tail -1
    fi
  )
  tag=$(basename "$loc")
  [ -n "$tag" ] && [ "$tag" != "latest" ] || err "could not resolve latest release tag"
fi
info "installing ${BIN} ${tag} (${goos}/${goarch})"

# --- 다운로드 + 검증 ----------------------------------------------------------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

base="https://github.com/${REPO}/releases/download/${tag}"
fetch "${base}/${asset}" "${tmp}/${asset}" || err "download failed: ${base}/${asset}"

info "verifying checksum"
sums=$(fetch_stdout "${base}/checksums.txt") || err "could not fetch checksums.txt"
expected=$(printf '%s\n' "$sums" | awk -v a="$asset" '$2==a {print $1}')
[ -n "$expected" ] || err "checksums.txt has no entry for $asset"

if have sha256sum; then actual=$(sha256sum "${tmp}/${asset}" | awk '{print $1}')
elif have shasum;   then actual=$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')
else err "need sha256sum or shasum to verify download"; fi
[ "$actual" = "$expected" ] || err "checksum mismatch (expected $expected, got $actual)"

tar -xzf "${tmp}/${asset}" -C "$tmp" || err "extraction failed"
[ -f "${tmp}/${BIN}" ] || err "archive did not contain ${BIN}"
chmod 0755 "${tmp}/${BIN}"

# --- 설치 위치 결정 -----------------------------------------------------------
writable() { mkdir -p "$1" 2>/dev/null && [ -w "$1" ]; }

dir="${HTTPROVE_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if writable "$HOME/.local/bin"; then dir="$HOME/.local/bin"
  elif writable "/usr/local/bin"; then dir="/usr/local/bin"
  else dir="$HOME/.local/bin"; mkdir -p "$dir"; fi
fi

# --- 설치 + 별칭 --------------------------------------------------------------
if writable "$dir"; then
  install -m 0755 "${tmp}/${BIN}" "${dir}/${BIN}"
  ln -sf "$BIN" "${dir}/${ALIAS}"
else
  info "elevating with sudo to write ${dir}"
  sudo install -m 0755 "${tmp}/${BIN}" "${dir}/${BIN}"
  sudo ln -sf "$BIN" "${dir}/${ALIAS}"
fi

info "installed ${dir}/${BIN} (and ${ALIAS} alias)"
case ":${PATH}:" in
  *":${dir}:"*) : ;;
  *) info "note: ${dir} is not on your PATH — add it to use ${BIN}" ;;
esac
"${dir}/${BIN}" --version >/dev/null 2>&1 && info "run '${BIN} --help' to get started"
