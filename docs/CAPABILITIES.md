# What SystemLens can and can't detect

This describes what the deterministic engine (`core/correlate.py`, `logs/cluster.py`) actually
does, not what an LLM might claim in a summary. The LLM never discovers a cause on its own —
it only ranks and narrates candidates these rules already produced. If a failure mode isn't
listed below, the agent has no mechanism for finding it, regardless of which LLM provider
you configure.

## 0. Where signals come from

| Source | What it provides | Enabled by |
|---|---|---|
| Container output | Each mapped container's stdout/stderr, read through the Docker API. Every record knows which container emitted it. | `agent up`, or `add-project` on a compose project without `--logs` |
| Docker events | A container crash (non-zero exit), an OOM kill, or a health check turning `unhealthy`. These produce a finding even if the container logged nothing. A stop you asked for (`docker stop`, `compose down`, exit code 0) is not reported, and an event is skipped when the container's own log line for the same failure was just analysed. | on by default (`docker_events`) |
| Log files | Files matching the project's globs, tailed with rotation handling. A `docker compose logs --timestamps` file is recognised and each line attributed to its container. | `--logs` |

Secrets are redacted as records are read (credentials in URLs, `password=`/`token=`/
`api_key` values, bearer tokens, JWTs, well-known key prefixes), so they are not stored,
sent to the LLM, or pushed to a central server. Redaction is pattern-based: a secret in
a shape it does not recognise will pass through.

## 1. Signal categories it recognizes

Every record at `WARNING` or above becomes a signal and is counted. Its text is matched
against a fixed set of keyword rules (`logs/cluster.py`) to give it a category. Errors
and categorised warnings are analysed; an uncategorised warning (a startup notice, a
deprecation) is counted but not analysed.

| Category | Trigger keywords/patterns |
|---|---|
| `connection_refused` | "connection refused", "ECONNREFUSED" |
| `timeout` | "timeout", "timed out" |
| `oom` | "oom", "out of memory", "killed process", "memory limit" |
| `dns_failure` | "could not translate host", "name or service not known", "dns" |
| `traceback` | Python tracebacks, "exception in thread", Go/Rust `panic:`, "unhandled" |
| `permission_denied` | "permission denied", "EACCES" |
| `missing_file` | "no such file or directory", "ENOENT" |
| `health_check` | "unhealthy", "health check failed" |

Docker events add `container_exit` (and use `oom` and `health_check`). Anything else is
`generic`: it is still analysed, but only the container-state rules can apply to it.

For `connection_refused` / `timeout` / `dns_failure`, it also tries to extract a
**host:port** from the line, recognizing three shapes: `host=db port=5432` (libpq),
`at "db" (10.0.0.2), port 5432` (psycopg2), and plain `db:5432`. If none of these shapes
match, the category is still recorded but rule R1 (below) can't run for that line.

## 2. Correlation rules — the actual root-cause logic

These run only when Docker is reachable. If it isn't, the agent falls back to a single
`R0` "log-only" note with low confidence — it will not fabricate a container-level cause
without container data.

| Rule | Detects | How |
|---|---|---|
| **R1** | The specific container behind a `connection_refused`/`timeout`/`dns_failure` | Resolves the host from the log line to a container by name, Compose service name, network alias, or IP; reports its current state |
| **R2** | A container that crashed and took a dependent down with it | A container that exited within the correlation window (default 120s) before the error; confidence decays the further back the exit was |
| **R3** | Out-of-memory kills | `OOMKilled=true` (confidence 0.9). Exit code 137 without that flag is reported as "killed with SIGKILL, OOM not confirmed" (0.5), because `docker kill` and stop timeouts also exit 137 |
| **R4** | Failing or still-starting health checks | Container health state is `unhealthy` (confidence 0.75) or `starting` (confidence 0.35 — weaker evidence, but relevant for a slow-starting or flapping service) |
| **R5** | A failure caused by an upstream dependency | Walks Compose `depends_on`; flags a running service whose dependency is down or unhealthy |
| **R6** | "You've seen this exact error before" | Exact fingerprint match against a stored resolution from `agent resolve`. The finding is produced from memory, with no LLM call (`memory.reuse_resolutions`) |

### Scoping: which facts count as candidates

R2–R5 describe container state, which is true for the whole project. A fact is offered
as a candidate cause only when its container is **linked** to the signal:

- the container that emitted the signal (its origin),
- the container the signal was trying to reach (R1's target),
- a container the triggering line names, or
- a Compose `depends_on` dependency of any of those, but only for kinds of failure a
  down dependency can explain: connection errors, timeouts, DNS failures, health check
  failures, container exits and unclassified errors. A traceback, missing file,
  permission error or OOM kill is not linked to a dependency's state.

Every other fact is still shown to the LLM, in a separate "co-occurring" section with
its confidence capped at 0.3, and with an instruction not to treat it as a cause. A log
file with no container identity and no host in the line has no origin and no target, so
all container facts for it are co-occurring.

### Grounding check

After the LLM answers, two deterministic checks run (`core/grounding.py`):

1. Quoted `evidence` must be a real substring of what was shown; anything else is dropped.
2. The conclusion must be about a linked container. Naming an unlinked container as the
   affected component downgrades the verdict to `insufficient_evidence`; mentioning one
   in the root cause downgrades `root_cause_identified` to `probable_cause` and caps
   confidence at 0.5. The reason is appended to the finding's assumptions.

A container named in the triggering line itself counts as linked. The check cannot judge
a wrong explanation that only involves linked containers, or one about something that
is not a container at all.

## 3. Container→project mapping

Correlation only works for containers the agent can attribute to the right project. Resolution
order: explicit config override → Compose project/service labels → Compose working-dir label →
name-prefix guess (last resort, flagged low-confidence). Containers with none of these signals
aren't correlated.

## 4. Deduplication and memory

- Identical errors (after masking UUIDs, timestamps, IPs, hex, and numbers) collapse to one
  **fingerprint** and are analyzed once, then suppressed until a cooldown elapses or the
  container state differs from what the last analysis saw (at most once every
  `min_reanalyze_seconds`).
- A resolution comes from `agent resolve <fingerprint> --note "..."` or from a verified
  fix (below). A resolved fingerprint that recurs is answered from memory.
- `agent mute <fingerprint>` stops analysis and notification for an issue; it is still
  counted.
- The latest evidence bundle per fingerprint is kept on disk (`eval.record_bundles`).
  `agent explain`, `agent investigate` and `agent eval init` read it.

## 5. What the follow-up agents may do

| Agent | May | May not |
|---|---|---|
| **Investigator** (`agent investigate`, or automatic with `investigator.auto`) | Read one of this project's containers' state or last 200 log lines, read the project's compose file, test whether a localhost port accepts connections. At most `max_steps` calls. | Name a container outside the project, reach any host but localhost, change anything. Its conclusion passes the same evidence and grounding checks. |
| **Remediator** (`agent fix`) | Show the suggested fix and classify it: `safe` (a plain `docker compose up -d/restart/start` or `docker restart/start`), `review` (any other command), `manual` (no command). | Run anything unless `remediation.allow_execute` is on and you pass `--run`; even then only `safe` commands, only naming this project's services or containers, never through a shell. |
| **Verifier** (automatic) | After `agent fix --applied` or a successful `--run`, mark the fix `failed` if the issue recurs, or `verified` after `verify_minutes` of quiet, saving it as the resolution. | Nothing else; it uses no LLM. It only knows the issue stopped appearing, not why. |
| **Ask** (`agent ask`) | Answer from stored findings, citing their ids. | Cite a finding that does not exist (dropped); an answer with no valid citation is labelled unsupported. |
| **Digest** (`agent digest`) | Summarise counts from the database; `--llm` adds a narrative paragraph. | — |

## 6. Provider behaviour

- Rate limits and transient errors are retried up to `llm.max_retries` times, waiting as
  the provider asks, for at most 20 seconds in total per analysis.
- A request rejected as too large is retried with half the evidence, down to 1,500
  characters.
- `llm.fallback` is used when the primary provider still fails.
- A failed analysis counts against the cooldown and hourly cap, so a broken provider is
  not hammered. `agent status` shows failed analyses in the last hour.

## 7. What it does *not* detect

- **Anything not represented in a log line or Docker's own state.** No metrics scraping, no
  network-level packet inspection, no application-internal state beyond what gets logged.
- **Novel logic bugs, race conditions, or data corruption** whose only symptom is "wrong
  output" rather than an error/exception/timeout in a log.
- **Cross-container causes outside the rules above** — e.g., a slow SQL query with no
  timeout logged, a misconfigured environment variable, a bad deploy that doesn't crash
  anything. If it doesn't produce a matching signal category or container state change,
  no candidate is generated for the LLM to reason about.
- **Kubernetes, remote hosts, or non-Docker processes** — this build only talks to a local
  Docker daemon.

## Known limits

- **File logs without container identity get weaker correlation.** With no origin, only
  a host or container named in the line can link a container to the signal. Use
  container streaming where possible.
- **An OOM kill of a child process that leaves the container running is not reported**;
  only an OOM followed by the container exiting is.
- **Redaction and the grounding check are pattern-based**, as described above.
- **Accuracy depends on the model and has not been benchmarked.** `agent eval` and the
  example suite exist to measure it; the suite's deterministic half passes, and no
  model results are recorded in this repository. Run it against your own provider.
- **The Ollama path and the investigator, ask and digest narratives have only been
  exercised with test doubles**, not against a live model.
- **Python 3.10 and 3.11 are declared supported but only 3.12 has been run.**
