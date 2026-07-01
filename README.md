# httprove

> probe + prove your HTTP services.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/x-mesh/httprove?sort=semver)](https://github.com/x-mesh/httprove/releases)
[![Homebrew](https://img.shields.io/badge/homebrew-x--mesh%2Ftap-orange)](https://github.com/x-mesh/homebrew-tap)

[한국어](README.ko.md) · **English**

An HTTP(S) service diagnostics tool for SREs. It breaks every phase of a request
into a latency waterfall, inspects TLS certificates, and can probe continuously
like `ping`. Both a CLI and a TUI are supported.

There are two commands — the full name **`httprove`** and the short alias **`hpr`**
(they are identical; every example in this document works with `hpr` too).

```
DNS      ▕██▏              12.3 ms
TCP        ▕███▏           18.1 ms
TLS           ▕█████▏      33.9 ms
TTFB               ▕████▏  51.2 ms
Download               ▕▏   2.1 ms
Total                     117.6 ms
```

## Features

- **Per-phase waterfall** — splits DNS/TCP/TLS/TTFB/Download to pinpoint the bottleneck
- **Deep TLS inspection** — version/cipher/key-exchange, chain expiry (weakest link)·SAN·issuer, handshake-failure cause decoding, chain completeness + AIA repair
- **Health verdict** — `--verdict` gives PASS/DEGRADED/DOWN plus a one-line rationale, `--explain` for plain-language explanation
- **Backend & path localization** — `--fanout` (per-IP), `--all-families` (v4/v6), `--via` (multi-resolver), `--asn` (IP ASN/org/country + CDN/cloud/origin), `trace` (traceroute)
- **Change tracking** — `diff` (compare two captures), `--since-good` (fingerprint drift vs. last-known-good)
- **Continuous monitoring** — ping mode + percentile stats, live TUI dashboard, multi-target
- **Synthetic monitoring** — `--expect-*` assertions (exit code 3), `--warn` threshold highlighting
- **Integration** — JSON/NDJSON, Prometheus (`--prom`/`--listen`), OTLP (`--otlp`), HTML report (`--report`)
- **Capture** — `--trap` (freeze on first failure), `--record`/`replay` (record & replay incidents)
- **DNS control** — `--dns` (resolve through chosen servers, not the system resolver), `--resolve` (bypass DNS: bare IP or curl-style `host:port:addr`)
- **Operations** — keep-alive mode, bulk certificate check (`--cert-check`), baseline comparison
- **Security & ops diagnostics** — `--tls-grade` (A–F TLS connection scorecard), `--cache-audit`
  (CDN HIT/MISS + cache anti-patterns), `--on-breach` (ping-mode webhook alerting),
  `--blackbox-config` (blackbox_exporter drop-in: modules YAML + `/probe` endpoint)
- **Request inspection** — `serve` runs a local echo server that dumps every incoming request
  (method/headers/body) and echoes it back as JSON (httpbin/RequestBin-style); mock responses
  (`--status`/`--delay`/`--respond-*`), NDJSON (`--json`), and a `GET /__requests` capture log
- **Two commands** — `httprove` (full)/`hpr` (short), self-update via `httprove update`

## What it measures

Every probe **establishes a fresh connection directly** and measures each phase
(no connection-pool reuse — the goal is to measure the full stack every time):

| Phase | Meaning | Suspect when slow |
|-------|---------|-------------------|
| DNS | Name resolution (`getaddrinfo`) | Resolver, TTL, negative cache |
| TCP | TCP 3-way handshake | Network RTT, SYN drop, firewall |
| TLS | TLS handshake (rustls) | Cert chain size, OCSP, TLS version |
| TTFB | Request sent → response headers received | **Server processing time**, upstream, DB |
| Download | Full response body received | Bandwidth, response size, compression |

Also collected: negotiated HTTP version (ALPN h2/http1.1), TLS version/cipher/key-exchange
group (X25519, etc.), certificate chain (expiry, D-day, SAN, issuer, key/signature algorithm,
chain structure), full DNS records, local socket address (source IP), response size/transfer rate,
and key response headers (server, content-type, cache/CDN status).

## Installation

### Homebrew (recommended)

```bash
brew install x-mesh/tap/httprove
```

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/x-mesh/httprove/main/install.sh | sh
```

Detects your OS/architecture, downloads the latest release binary, verifies it with
sha256, installs it to `~/.local/bin` (or `/usr/local/bin`), and creates the `hpr` alias.

### Update

Updates itself to the latest version according to how it was installed:

```bash
httprove update              # delegates to brew upgrade if installed via brew; otherwise self-replaces the binary
httprove update --check      # only check for a new version (up-to-date = exit 0, update available = exit 1)
httprove update --dry-run    # print what it would do, without doing it
httprove update --to v0.2.0  # pin a specific version (manual installs)
```

### Build from source

```bash
make release          # release build → ./target/release/{httprove,hpr}
make build            # debug build → ./target/debug/{httprove,hpr}
make ci               # format check + clippy + tests + release build
make smoke            # smoke test against a live service
make install          # overwrite the httprove/hpr on your PATH with this build
                      #   (auto-detects the active location; override: make install PREFIX=/usr/local/bin)
make install-cargo    # install to ~/.cargo/bin via cargo install
make help             # list all targets
```

You can also use cargo directly: `cargo build --release`

## Usage

### One-shot check (waterfall + certificate detail)

```bash
httprove https://api.example.com
httprove https://api.example.com -v        # response headers + full certificate chain
httprove https://api.example.com --json    # JSON for scripting
```

### ping mode (continuous monitoring)

```bash
httprove -c 0 https://api.example.com            # 1s interval until Ctrl-C
httprove -c 100 -i 0.5 https://api.example.com   # 100 probes at 0.5s interval
```

```
seq=0 93.184.216.34 200 dns=12.3ms tcp=18.1ms tls=33.9ms ttfb=51.2ms dl=2.1ms total=117.6ms
seq=1 93.184.216.34 200 dns=1.1ms tcp=17.9ms tls=32.2ms ttfb=49.8ms dl=2.0ms total=103.0ms
^C
--- https://api.example.com httprove statistics ---
2 probes: 2 ok, 0 failed (0.0% loss)
phase        min       avg       p50       p95       max    stddev
...
```

Exit codes: all probes passed `0` │ network failure/execution error `1` │
network succeeded but `--expect-*` assertion violated `3` (for cron/alert integration).

### Assertions (synthetic monitoring)

```bash
httprove --expect-status 200 --expect-ttfb 500 --expect-body '"ok"' https://api.example.com/health
httprove --expect-status 2xx,3xx https://example.com     # class notation supported
httprove --expect-cert-days 30 https://api.example.com   # exit 3 if cert has fewer than 30 days left
```

On violation, `EXPECT-FAIL: …` is shown in the ping line / one-shot output and the process exits with code 3.

### Threshold highlighting

```bash
httprove -c 0 --warn ttfb=300 --warn total=800 https://api.example.com
```

Phases over threshold are highlighted in yellow (≥1x) and red (≥2x) (CLI/TUI alike).

### keep-alive mode (connection cost vs. server time)

```bash
httprove --keepalive -c 0 https://api.example.com
```

Only the first probe does DNS/TCP/TLS; subsequent probes send requests over the same
connection (shown as `conn=reused`). Comparing against fresh-connection probes lets you
separate "is connection setup slow, or is server processing slow?".

### Multi-target

```bash
httprove -c 0 https://a.example.com https://b.example.com   # interleaved with [host] tags
httprove --tui https://a.example.com https://b.example.com  # overlaid charts, switch with tab
```

### Prometheus integration

```bash
# snapshot for the node_exporter textfile collector
httprove -c 10 --prom https://api.example.com > /var/lib/node_exporter/httprove.prom

# long-running exporter (infinite probing + /metrics server)
httprove --listen 0.0.0.0:9912 -i 5 https://api.example.com https://b.example.com
curl localhost:9912/metrics
```

`httprove_phase_milliseconds{target,phase,stat}`, `httprove_probes_total`,
`httprove_cert_expiry_days`, and other per-phase percentiles are exposed as-is.

Ready-to-use recording rules (availability/Apdex/SLO burn-rate/error-budget/z-score),
alerts, and a Grafana dashboard are in [`examples/`](examples/README.md).

### Baseline comparison (detect regressions across a deploy)

```bash
httprove -c 30 --save before.json https://api.example.com    # before deploy
httprove -c 30 --compare before.json https://api.example.com # after deploy: p50/p95 delta% table
```

### Bulk certificate check

```bash
httprove --cert-check api.example.com b.example.com:8443 @domains.txt
httprove --cert-check --json @domains.txt | jq '.[] | select(.days_remaining < 30)'
```

Outputs a table sorted by nearest expiry. Exits 1 if any are EXPIRED or fail to connect.

### TUI dashboard

```bash
httprove --tui https://api.example.com
```

Live latency chart + latest waterfall + per-phase stats + probe history (bottom,
ping-line style showing recent results one per line — failures in red).
Keys: `q` quit, `space` pause, `r` reset stats.

### Troubleshooting options

```bash
httprove -L https://example.com              # follow redirects (measured per hop)
httprove --resolve 10.0.0.5 https://api.example.com   # hit a specific backend directly (bypass DNS, keep SNI/Host)
httprove --resolve api.example.com:443:10.0.0.5 https://api.example.com   # curl-style per-host pin (in-tool /etc/hosts, repeatable)
httprove --dns 1.1.1.1,8.8.8.8 https://api.example.com   # resolve through specific DNS servers instead of the system resolver
httprove -4 https://api.example.com          # force IPv4 (-6: IPv6)
httprove --http1 https://api.example.com     # force HTTP/1.1 (disable h2 negotiation)
httprove -k https://expired.internal         # skip certificate verification (chain info still collected)
httprove -t 3 https://api.example.com        # 3s timeout for the whole probe
httprove -X POST -d '{"ping":1}' -H 'Content-Type: application/json' https://api.example.com/health
httprove --cert-warn 14 https://api.example.com   # warn from 14 days before expiry
```

On failure it reports **which phase** failed (`ERROR(dns)`, `ERROR(tls): certificate has expired`, …).

### JSON output (monitoring-pipeline integration)

```bash
httprove -c 10 --json https://api.example.com | jq 'select(.type=="probe") | .total_ms'
```

- One line per probe: `{"type":"probe","seq":0,"hops":[{"timings":{...},"cert_chain":[...],...}],...}`
- A summary line at the end: `{"type":"summary","phases":{"ttfb":{"p95":...},...},"status_counts":{"200":10},...}`

### Inspect incoming requests (`serve`)

The other direction: instead of sending requests, run a server that shows what a client
(your app, frontend, or a webhook sender) actually transmits — a local httpbin/RequestBin.

```bash
httprove serve :8080                       # bind 0.0.0.0:8080; dump each request + echo it back as JSON
httprove serve                             # default 127.0.0.1:8080 (local only)
httprove serve :8080 --json                # one NDJSON line per request (pipe to a file / jq)
httprove serve :8080 --status 503 --delay 2s   # mock a slow, failing endpoint (test client retry/timeout)
httprove serve :8080 --respond-body '{"ok":true}' --respond-type application/json   # fixed mock response
httprove serve :8443 --tls-cert cert.pem --tls-key key.pem   # HTTPS (provide a cert)
```

- Each request is printed to the console (method, target, headers, pretty body) and, by default,
  echoed back to the client as a JSON object (`method`/`target`/`query`/`headers`/`body`).
- `GET /__requests` returns the recent requests as JSON (`--keep N`, default 100);
  `GET /__requests/<seq>` returns one. `/__`-prefixed paths are not captured/echoed.
- `--no-echo` replies with a short `ok` instead of echoing; `--respond-header "K: V"` adds headers.
- HTTPS needs a certificate (`--tls-cert`/`--tls-key`). Generate a self-signed one with:
  `openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout key.pem -out cert.pem -subj '/CN=localhost'`

## Deep diagnosis (from numbers to conclusions)

It doesn't stop at showing numbers — it determines "what is wrong, and why".

### Health verdict + plain-language explanation

```bash
httprove --verdict https://api.example.com   # ends with PASS/DEGRADED/DOWN + one-line rationale
httprove --explain https://api.example.com   # "TCP 39ms, server 21ms (TTFB), 60ms total over HTTP/2"
```

Exit code is PASS=0 / DOWN=1, ready to use directly in synthetic monitoring.

### Backend & path localization

```bash
httprove --fanout https://api.example.com          # probe every DNS IP individually, catch a bad backend (outlier)
httprove --all-families https://api.example.com    # IPv4 vs IPv6 phase-by-phase comparison
httprove --via 1.1.1.1,8.8.8.8 https://api.example.com   # compare response IP/POP per resolver (--ecs for client-subnet)
httprove --dns 1.1.1.1 https://api.example.com     # probe through a chosen resolver (normal flow; combine with -c/--json/--verdict)
httprove trace https://api.example.com             # system traceroute + TLS-terminating hop annotation
httprove --asn https://api.example.com             # connected IP's ASN/org/country (Team Cymru) + PTR + infra (CDN/cloud/origin)
```

### Deep TLS trust

```bash
httprove --check-chain https://api.example.com   # missing intermediate certificate + AIA repair feasibility
httprove --tls-grade https://api.example.com     # A–F connection grade (protocol/cipher/kx/HSTS/chain)
httprove https://expired.example.com             # translates handshake failure into cause + fix (hint:)
```

`--check-chain` catches incomplete chains that "work in the browser but fail in curl/Go".
The certificate block always shows the weakest-link expiry of the whole chain (`weakest:`).

### Cache · alerting · blackbox_exporter

```bash
httprove --cache-audit https://cdn.example.com   # CDN HIT/MISS, edge, age, cache-busting anti-patterns
httprove -c 0 --on-breach https://hooks.example/alert https://api.example.com   # webhook on breach (verdict != PASS)
httprove --blackbox-config blackbox.yml --listen :9115 placeholder.invalid      # blackbox drop-in: /probe?target=&module=
```

`--on-breach` posts a JSON alert in ping mode, debounced with `--breach-after N` / `--cooldown SECS`
(plus `--on-recover`). `--blackbox-config` reads an existing blackbox `modules:` YAML and — with
`--listen` — serves a compatible `/probe?target=&module=` endpoint, so existing Prometheus scrape
configs/alerts keep working while each probe gains httprove's per-phase breakdown (the CLI target
is a placeholder in `/probe` mode; targets come from the query).

### Change tracking · capture · integration

```bash
httprove https://x --json > before.json          # compare two points in time / endpoints
httprove diff before.json after.json             # only the changed fields (cert serial, IP set, TLS, headers…)
httprove --since-good /var/lib/httprove/x.state https://x   # non-0 when fingerprint drifts from last-known-good
httprove --since-good x.state --on-change https://x         # CI: non-0 exit when fingerprint changes (deploy verification)
httprove --annotate-deploy before.json https://x            # annotate changes vs. a saved probe
httprove --trap -c 0 https://x                   # freeze on first failure, dump the whole transaction
httprove --record sess.json -c 100 https://x && httprove replay sess.json   # record/replay an incident
httprove --report out.html https://x             # single self-contained HTML report for sharing
httprove --otlp http://collector:4318 --traceparent https://x   # export OTLP span + inject traceparent
```

`--on-change` flips the exit code to non-0 when the fingerprint (cert·IP·TLS·headers) differs
from the previous good state — used to catch "unintended changes" after a deploy in CI.

## Scenarios

- **"The service is slow but I don't know where"** → one-shot waterfall + `--verdict` to decide whether DNS/network/server is the bottleneck
- **"Is everything slow, or just one node?"** → `--fanout` to compare per backend IP and catch the bad node
- **"What changed?"** → `--since-good` or `diff` to track cert/IP/TLS/header changes
- **Compare latency across a deploy** → `--save`/`--compare` for p50/p95 delta%
- **Track intermittent timeouts** → `--trap` to freeze on first failure, or `--tui` to observe
- **Certificate expiry/chain checks** → `--cert-warn`·`--check-chain`·`--cert-check` for cron alerts
- **Synthetic monitoring** → `--expect-*` (exit 3) + `--otlp` to feed a tracing backend

## Exit codes

| Code | Meaning |
|:---:|---------|
| 0 | All probes passed (verdict PASS/DEGRADED) |
| 1 | Network failure / execution error (verdict DOWN), or a defect found by `--fanout`/`--cert-check` etc. |
| 3 | Network succeeded but an `--expect-*` assertion was violated |

## Structure

```
src/
├── lib.rs         # entry point cli_main: subcommand/mode routing, signals, exit codes
├── main.rs        # `httprove` entry point (calls lib::cli_main)
├── bin/hpr.rs     # `hpr` entry point (same binary)
├── cli.rs         # clap args → ProbeConfig / Expectations / WarnThresholds
├── types.rs       # shared types (ProbeResult/CertInfo/Verdict/Fingerprint/ChainAnalysis, Serialize+Deserialize)
├── probe.rs       # core: manual DNS/TCP/TLS/HTTP connection + per-phase measurement, keepalive (rustls ring + hyper)
├── cert.rs        # x509 chain analysis (incl. SPKI pin)
├── cert_check.rs  # --cert-check bulk check
├── hash.rs        # shared SHA-256 (dependency-free; cert pin & self-update verification)
├── verdict.rs     # health verdict PASS/DEGRADED/DOWN (--verdict/--explain)
├── diff.rs        # fingerprint extraction + probe JSON diff (diff subcommand/--since-good)
├── fanout.rs      # --fanout (per-IP), --all-families (v4/v6)
├── dns.rs         # custom DNS-over-UDP client (--via multi-resolver compare + --dns normal-flow resolver override + --ecs)
├── trace.rs       # system traceroute + TLS-terminating hop annotation
├── chain.rs       # chain completeness/AIA repair, weakest-link expiry, handshake error decoder
├── record.rs      # --record/replay, --trap (freeze on first failure)
├── otlp.rs        # OTLP/HTTP span export, Server-Timing parsing, traceparent
├── exporter.rs    # --listen Prometheus exporter
├── stats.rs       # Welford + ring-buffer percentiles
├── runner.rs      # probe loop (multi-target/interval/pause/cancel)
├── update/        # httprove update — install-method detection + self-replacement
├── output/        # text (waterfall/ping/summary) + JSON + prom + baseline + HTML report
└── tui/           # ratatui dashboard (multi-target)
```

## License

[MIT](LICENSE)
