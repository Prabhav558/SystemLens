# SystemLens roadmap

Order of work: fix correctness and security, make ingestion zero-config, build a way
to measure accuracy, and only then add agents. Agents built on unreliable evidence
repeat wrong answers more fluently.

Status key: **done**, **partial**, **planned**.

## Phase 0: fix what is wrong

| # | Problem | Fix | Status |
|---|---|---|---|
| 0.1 | Stored XSS in the central dashboard: finding text rendered through `innerHTML`, with the API key in `localStorage` | DOM rendering with `textContent`, script and styles moved out of the page, CSP header | done (not yet opened in a browser) |
| 0.2 | A resolved fingerprint still called the LLM, although the docs said it did not | Short-circuit: known resolution produces a finding from memory | done |
| 0.3 | Confidently wrong root causes: every unhealthy fact in the project was attached to every signal | Candidates scoped to the signal's origin, target, named containers and relevant dependencies; code-level grounding check downgrades unsupported claims | done |
| 0.4 | Admin key compared with `!=` | `hmac.compare_digest` | done |
| 0.5 | Raw log lines sent to a hosted LLM unredacted | Pattern-based redaction at ingestion | done |
| 0.6 | Nothing is ever pruned | `retention.days`, prune on startup, resolutions kept | done |

Also fixed along the way: exit code 137 was reported as a confirmed OOM kill; a
`docker compose logs` prefix stopped tracebacks from being assembled into one record;
uncategorised warnings were sent for analysis; a state change could bypass the cooldown
on every restart of a crash-looping container.

## Phase 1: zero-config ingestion

| # | Item | Status |
|---|---|---|
| 1.1 | Native Docker log streaming; every line carries its container identity | done |
| 1.2 | Docker events (`die`, `oom`, `health_status`) as triggers, so container-only failures get their own finding | done |
| 1.3 | `agent up`: detect compose file, register, stream, start; live pick-up of new projects | done |
| 1.4 | `agent projects`, `agent remove-project`, `agent service install`, single-daemon lock, `--verbose` | done (`service install --enable` not yet run against a real systemd) |
| 1.5 | Distribution: wheel and sdist build and install cleanly; Dockerfile and compose files | partial: not published to PyPI (needs an account) |

## Phase 2: measure, then improve accuracy

| # | Item | Status |
|---|---|---|
| 2.1 | `agent eval`: replay recorded evidence against an answer key; example suite from a real broken stack | done; deterministic half passes 11/11, no live-model run yet |
| 2.2 | Provider resilience: `Retry-After`, evidence shrinking on "too large", configurable budget, fallback provider | done (tested with simulated provider errors) |
| 2.3 | Batched occurrence counts | done |

## Phase 3: agents

| Agent | Job | Guardrail | Status |
|---|---|---|---|
| Investigator | On an inconclusive finding, a short read-only tool loop | Project-scoped read-only tools, capped steps, same checks on the result; automatic use is opt-in | done (not yet run against a live model) |
| Verifier | Watch an applied fix; save it as the resolution if the issue stays quiet | No LLM | done |
| Remediator | `agent fix` shows the fix and its risk class | Propose-only by default; `--run` needs `remediation.allow_execute` and only runs allowlisted restarts | done |
| Digest | Summary of new, recurring and resolved issues; optional daily notification | Numbers come from the database; narrative is optional | done |
| Ask | `agent ask` over stored findings | Citations validated; uncited answers labelled | done (not yet run against a live model) |

## Phase 4: where findings show up

| Item | Status |
|---|---|
| Notification sinks: Slack, Discord, webhook, desktop, with a threshold | done (webhooks tested against a mock, not the real services) |
| MCP server exposing findings and `resolve` | done |
| `agent watch` live terminal view | done |
| Central server: retry outbox, backfill, key revocation, throttling | done |
| Local dashboard showing findings | done |

## Added after re-evaluation

| Item | Status |
|---|---|
| `agent mute` / `unmute` for noisy issues | done |
| `agent explain`: a finding with its evidence and what was and was not linked | done |
| `agent doctor`: provider reachability, per-project container visibility, mistyped config keys | done |
| `agent status`: failed analyses in the last hour | done |
| `--json` on `status`, `findings`, `eval run` | done |
| `systemlens.ignore=true` container label | done |

## Next

| Item | Why |
|---|---|
| Run the example suite against real models and record the results | The one thing that says how good the answers are |
| Publish to PyPI and a container registry | Needs the owner's accounts |
| Per-project settings (cooldown, notification threshold) | One global config is coarse for mixed projects |
| A socket proxy example for the containerised agent | Narrower than mounting the Docker socket read-only |

## Not planned

Kubernetes or remote hosts, real embedding models, and replacing the deterministic
correlator with an LLM agent.
