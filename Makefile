# httprove 빌드/검증 Makefile — `make help`로 타깃 목록 확인

CARGO ?= cargo
BIN   := httprove
DEBUG_BIN   := target/debug/$(BIN)
RELEASE_BIN := target/release/$(BIN)

# 설치 위치: PATH에 이미 잡히는 httprove를 따라가 그 자리를 덮는다(brew/cargo 무관).
# 없으면 ~/.cargo/bin. 다른 곳에 깔려면: make install PREFIX=/usr/local/bin
PREFIX ?= $(shell dirname "$$(command -v $(BIN) 2>/dev/null || echo $$HOME/.cargo/bin/$(BIN))")

.DEFAULT_GOAL := help

.PHONY: help build release run test lint fmt fmt-check check ci smoke install install-cargo clean

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

install: release ## PATH의 httprove/hpr를 새 릴리스 빌드로 덮어쓴다 (PREFIX=dir로 위치 지정)
	@echo "→ installing httprove + hpr to $(PREFIX)"
	@for n in httprove hpr; do \
	  install -m 0755 target/release/$$n "$(PREFIX)/$$n" 2>/dev/null \
	    || sudo install -m 0755 target/release/$$n "$(PREFIX)/$$n"; \
	done
	@echo "✓ installed: $$("$(PREFIX)/httprove" --version)  → $(PREFIX)"
	@echo "  note: brew 본을 덮었다면 'brew upgrade/reinstall httprove' 시 되돌아갑니다."

install-cargo: ## ~/.cargo/bin에 설치 (cargo install --path .)
	$(CARGO) install --path . --locked

clean: ## 빌드 산출물 제거
	$(CARGO) clean
