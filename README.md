# TLS Certificate Inspector

Live TLS certificate inspection as an MCP server. Give it a hostname and it performs a real TLS handshake (with SNI), then reports the presented certificate: subject CN, issuer, validity window, days remaining, SAN list, negotiated TLS version, and whether the chain validates against the system trust store.

## Tools

| Tool | Description |
|------|-------------|
| `inspect_cert` | Inspect one host's TLS certificate. Input: `hostname` (protocol/port/path are stripped automatically), `port` (default 443). Returns subject CN, issuer, `valid_from`/`valid_to`, `days_remaining` (whole days, floored), `expired`, `san` (up to 50 DNS names), `tls_version_negotiated`, `chain_complete`, and `cached`. |
| `check_expiry_bulk` | Inspect up to 20 hosts at once (concurrency capped at 5, 10s per host). Returns results sorted by `days_remaining` ascending, `warnings.critical` (<7 days, includes expired), `warnings.warning` (7–29 days), and `checked_at`. Per-host failures become `{hostname, error}` entries — the batch never fails wholesale. |

Both tools return structured JSON in `content` and `structuredContent`. Every input is validated with Zod (`.describe()` on all fields); failures return `isError: true` with an LLM-friendly message and a next-step suggestion — the server never crashes on bad input.

## Data source

**Live TLS handshakes via Node's built-in `tls` module — no upstream API, no cost, no API key.**

- First handshake uses `rejectUnauthorized: false` + SNI so the presented certificate is captured even from misconfigured, self-signed, or expired hosts.
- A second authorized handshake determines `chain_complete`: true only if the default system trust store accepts the chain for that hostname.
- If `HTTPS_PROXY`/`ALL_PROXY` is set (and the host isn't in `NO_PROXY`), traffic is tunnelled via HTTP CONNECT — standard proxy semantics, a no-op on MCPize Cloud.
- One transient retry (ECONNRESET/EPIPE/timeout) on the first handshake.

## Pricing

- **Free:** 100 tool calls/day (in-memory per-day counter, configurable via `FREE_DAILY_LIMIT` env var).
- **x402 pay-per-call:** $0.01 USDC per call on both tools once the free quota is exceeded.

Results are cached in memory for 1 hour (`cached: true` marks a cache hit).

## Limitations

- **Publicly reachable hosts only.** Hosts behind firewalls, VPNs, or requiring client certificates can't be inspected; the tool reports a clear error suggesting the fix.
- **`chain_complete` reflects the default system trust store** of the machine running the server. A chain that validates in a browser with extra root CAs installed may still report `false` here.
- **SAN list truncated at 50 entries** (DNS names only; IP SANs are dropped).
- **Expiry math is in whole days**, floored: a certificate with 5.5 hours left reports `days_remaining: 0`.
- **SNI is sent for DNS hostnames only**; IP literals connect without SNI.
- Free-tier usage is tracked in memory, so it resets if the server restarts.

## Local development

```bash
npm install
npm run dev      # tsx watch on :8080
npm test         # vitest (unit + live handshake tests)
npm run build    # tsc -> dist/
```

`GET /health` returns `{"status":"healthy"}`.
