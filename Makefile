# httprove 빌드/검증 Makefile — `make help`로 타깃 목록 확인

CARGO ?= cargo
BIN   := httprove
DEBUG_BIN   := target/debug/$(BIN)
RELEASE_BIN := target/release/$(BIN)

.DEFAULT_GOAL := help

.PHONY: help build release run test lint fmt fmt-check check ci smoke install clean

help: ## 타깃 목록 출력
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## 디버깅 빌드 (target/debug)
	$(CARGO) build

release: ## 릴리스 빌드 (최적화 + strip, target/release)
	$(CARGO) build --release

run: build ## 디버그 빌드 후 실행 (예: make run ARGS="https://example.com")
	$(DEBUG_BIN) $(ARGS)

test: ## 단위 테스트
	$(CARGO) test

lint: ## clippy (경고 = 실패)
	$(CARGO) clippy --all-targets -- -D warnings

fmt: ## 코드 포맷 적용
	$(CARGO) fmt

fmt-check: ## 포맷 검사만 (변경 없음)
	$(CARGO) fmt --check

check: ## 빠른 타입/컴파일 검사
	$(CARGO) check

ci: fmt-check lint test release ## CI 전체 게이트: 포맷 + 린트 + 테스트 + 릴리스 빌드

smoke: release ## 릴리스 바이너리로 실서비스 스모크 테스트
	$(RELEASE_BIN) --version
	$(RELEASE_BIN) https://example.com
	$(RELEASE_BIN) -c 2 -i 0.3 --json https://example.com | python3 -c "import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]; print('json ok')"

install: ## ~/.cargo/bin에 설치
	$(CARGO) install --path . --locked

clean: ## 빌드 산출물 제거
	$(CARGO) clean
