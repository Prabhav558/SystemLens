# Changelog

## 0.2.0

### Added
- `agent up`: register a Compose project and start watching it in one step.
- Container output is read directly from Docker; Docker events (crash, OOM kill,
  unhealthy) trigger findings on their own.
- Projects registered or removed while the daemon runs are picked up without a restart.
- `agent explain`, `agent investigate`, `agent fix`, `agent fixes`, `agent mute`,
  `agent ask`, `agent digest`, `agent watch`, `agent eval`, `agent mcp`,
  `agent notify-test`, `agent projects`, `agent remove-project`, `agent service`.
- Fix verification: an applied fix that holds is saved as the issue's resolution.
- Notifications to Slack, Discord, a webhook or the desktop, and a daily digest.
- Evaluation harness with an example suite recorded from a real broken stack.
- Central server: push outbox with retry, backfill, key revocation, idempotent ingest,
  per-client auth throttling, request size limit.
- Provider layer: retries that honour `Retry-After`, automatic evidence shrinking when a
  request is too large, optional fallback provider.
- Container image, deployment compose files, CI workflow.

### Changed
- Container facts are offered as causes only when linked to the signal; a code-level
  grounding check downgrades answers that blame an unlinked container.
- A resolved issue is answered from memory with no LLM call.
- Uncategorised warnings are counted but no longer analysed.
- Exit code 137 without Docker's OOM flag is no longer reported as a confirmed OOM kill.
- Occurrence counts are written in batches instead of once per log line.
- Fingerprints for `docker compose logs` files change, because the container prefix is
  now stripped from each line. Cooldowns and resolutions for those do not carry over.
- Ollama requests use `/api/chat`.

### Fixed
- Stored XSS in the central dashboard.
- Secrets in log lines were sent to the LLM; they are now redacted at ingestion.
- A timestamp such as `10:43:01` was parsed as host 10, port 43.
- Tracebacks in `docker compose logs` files were split into separate records.
- History was never pruned.

## 0.1.0

Initial version: log file watching, correlation rules R1–R6, Groq and Ollama
providers, CLI, local and central dashboards.
