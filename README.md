# SystemLens

A local agent that watches your Docker Compose projects, works out why something
failed, and tells you how to fix it.

It reads container output and Docker events as they happen, links each error to the
containers that can actually explain it (the one that logged it, the one it was trying
to reach, their dependencies), and asks an LLM to rank and explain that evidence. The
linking is deterministic Python; the model cannot blame a container the evidence does
not connect to the error, and "insufficient evidence" is an accepted answer.

```
$ cd myapp && agent up
watching 1 project(s)
╭──────────────── myapp :: 3ce83d45168f0c6b ─────────────────╮
│ component: myapp-db-1                                      │
│ root cause: backend cannot reach PostgreSQL; the db        │
│ container exited (code 1) 4s before the first refusal      │
│ fix: docker compose up -d db                               │
│ confidence: 0.90  verdict: root_cause_identified           │
╰────────────────────────────────────────────────────────────╯
```

## Install

```bash
./install.sh        # venv, dependencies, provider setup, health check
```

Two LLM providers are supported: **Ollama** (local, no key) and **Groq** (hosted).
See [INSTALL.md](INSTALL.md) for manual steps, provider setup and troubleshooting.

## Use

```bash
cd myapp            # a directory with a docker-compose.yml
agent up            # registers it and starts watching
```

No log files or flags are needed for a Compose project. For one that logs to files,
add `--logs "./logs/*.log"`. Run `agent up` in another project directory while the
daemon is running and it is picked up within a few seconds.

| To | Run |
|---|---|
| see what it found | `agent findings`, `agent watch` (live), `agent status` |
| see one finding with its evidence | `agent explain <fingerprint>` |
| dig further into an inconclusive one | `agent investigate <fingerprint>` |
| see the suggested fix and its risk | `agent fix <fingerprint>` |
| tell it you applied the fix | `agent fix <fingerprint> --applied`, then `agent fixes` |
| record what fixed something | `agent resolve <fingerprint> --note "..."` |
| silence a noisy issue | `agent mute <fingerprint>` |
| ask about past incidents | `agent ask "why did the worker fail last night?"` |
| get a summary | `agent digest` |
| check the setup | `agent doctor` |
| run it in the background | `agent service install --enable` |

A fingerprint can be shortened to any unique prefix. Most read commands take `--json`.

## What it does for you

- **Finds the cause across containers.** A backend error is traced to the database
  container that exited seconds earlier.
- **Catches silent failures.** A crash, OOM kill or failing health check produces a
  finding even if the container logged nothing.
- **Remembers fixes.** Once an issue is resolved (by you, or verified automatically
  after `agent fix --applied`), its recurrence is answered from memory with no LLM call.
- **Verifies fixes.** After a fix is applied the issue is watched; if it stays quiet
  the fix is saved as the resolution, and if it recurs you are told the fix did not hold.
- **Stays quiet.** Identical errors collapse to one issue, analysed once per cooldown;
  hourly and daily budgets cap LLM use; noisy issues can be muted.
- **Notifies you.** Slack, Discord, a generic webhook or desktop popups, plus an
  optional daily digest.
- **Works with your tools.** `agent mcp` exposes findings to MCP clients such as Claude
  Code; `agent serve` is a local dashboard; a central server collects findings from
  several machines behind per-agent API keys.

Running a suggested fix for you is off by default. When enabled
(`remediation.allow_execute`), only `docker compose up -d/restart/start` and
`docker restart/start` on this project's own services can be run, after confirmation.

## Measuring accuracy

```bash
agent eval run examples/eval/error-project/suite.yaml --no-llm   # correlator only
agent eval run examples/eval/error-project/suite.yaml            # with your model
agent eval init myapp                                            # build a suite from your own incidents
```

The example suite is evidence recorded from a deliberately broken seven-container
stack, with an answer key taken from that stack's source code. Run it against your
model before trusting the tool's verdicts; results vary by model.

## SDK

```python
from systemlens import Agent

async with Agent.from_config() as a:
    await a.add_project("./myapp")
    async for finding in a.watch():
        print(finding.analysis.root_cause, "->", finding.analysis.fix_suggestion)
```

## Documentation

- [INSTALL.md](INSTALL.md): installation, providers, troubleshooting
- [docs/CAPABILITIES.md](docs/CAPABILITIES.md): exactly what is detected, and what is not
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): background service, container image, central server, security
- [docs/ROADMAP.md](docs/ROADMAP.md): what is done and what is planned
- [examples/config.example.yaml](examples/config.example.yaml): every setting

## Development

```bash
pip install -e ".[dev,groq,api,faiss,mcp]"
pytest
```

The suite runs offline: Docker and the LLM are replaced by fakes.

## Licence

MIT. See [LICENSE](LICENSE).
