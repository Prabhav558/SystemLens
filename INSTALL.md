# Installing SystemLens

## Prerequisites

- **Linux or WSL2** (Ubuntu 22.04+/24.04 tested). Docker's WSL integration must be
  enabled if you're on WSL — without it, `docker` commands fail with no daemon found.
- **Python 3.10+**
- **Docker + Docker Compose**, reachable by the user running SystemLens (`docker ps`
  should work without `sudo`). Container correlation — the actual point of this tool —
  doesn't function without it; logs-only analysis still works if Docker is unreachable.
- **An LLM provider**: either **Ollama** running locally (`ollama serve`, no API key,
  no cost), or a **Groq** API key (free tier available at [console.groq.com](https://console.groq.com)).
  These are the only two supported providers.

## Quick install (recommended)

```bash
git clone <this-repo> SystemLens && cd SystemLens
./install.sh
```

This creates a venv, installs the package, and launches the interactive picker
(`agent init`) to choose your provider. Safe to re-run at any time — every step is
idempotent (an existing venv is reused, not recreated).

For a fully scripted install with no prompts (CI, provisioning, etc.):

```bash
./install.sh --provider groq --model openai/gpt-oss-120b
# or:
./install.sh --provider ollama --model llama3.1
```

Run `./install.sh --help` for the full flag list.

## Manual install

If you'd rather not run the script:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[groq,api,faiss]"    # or just "-e ." for ollama-only, no API extras needed
agent init
agent doctor
```

`agent init` asks for: provider (`ollama` or `groq`), model, and either an Ollama base
URL or the env var name holding your Groq key. It writes `~/.systemlens/config.yaml`.

`agent doctor` must show all green before continuing — it checks the Docker daemon,
the configured API key/URL, and that `~/.systemlens` is writable.

## Provider setup

### Groq (hosted API)

```bash
export GROQ_API_KEY=your-key-here
```

Put this in your shell profile (`~/.bashrc`/`~/.zshrc`) so it persists across
terminals — don't paste API keys directly into a chat session or commit them anywhere.

**Model name must include the `openai/` prefix** — Groq's actual model ID is
`openai/gpt-oss-120b`, not `gpt-oss-120b`. Using the bare name returns
`404 model_not_found`. Strict structured-output mode (which every request needs) is
only guaranteed on `openai/gpt-oss-20b` and `openai/gpt-oss-120b`; other Groq models
fall back to a best-effort JSON mode with a repair retry — less reliable, still works.

**The free tier is tight.** The limits observed while building this were 8,000 tokens
per minute and about 30 requests per minute; check your account for current values.
SystemLens retries on rate limits, shrinks the evidence when a request is rejected as
too large, and caps analyses per hour, so a busy project degrades to fewer analyses
rather than errors. A `fallback` provider (for example local Ollama) can be configured
in `config.yaml` for when Groq keeps refusing.

### Ollama (fully local)

```bash
ollama serve                    # if not already running
ollama pull llama3.1            # or whatever model you configured
```

No API key, no network calls, no cost. Slower and lower-quality reasoning than a
hosted model, generally.

## Registering and running a project

For a Docker Compose project, one command from its directory:

```bash
cd /path/to/your/app
agent up
```

It registers the project (once) and starts watching. Container stdout/stderr is read
straight from Docker, and container crashes, OOM kills and failing health checks
trigger findings on their own, so no log files or `--logs` flag are needed.

For a project that writes log files instead, or in addition:

```bash
agent up /path/to/your/app --logs "/path/to/your/app/logs/*.log"
```

With `--logs`, container streaming is off by default so lines that reach both a file
and stdout are not analysed twice; add `--docker-logs` to have both.

Managing projects:

```bash
agent projects                      # what is registered and what each one watches
agent remove-project myapp          # history is kept; add --purge to delete it
```

If you registered a project earlier with a tee'd `docker compose logs` file, switch it
over: stop the `docker compose logs -f` process, then
`agent remove-project <name> && agent up /path/to/project`.

## Running in the background, notifications, central server

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): `agent service install --enable` for a
systemd service, notification targets, the container image and the central server.

## `pip install` fails with "externally-managed-environment"

You tried to install outside a venv, against your system Python. This is expected —
Debian/Ubuntu block that on purpose (PEP 668). The fix is always to use a venv (which
`install.sh` and the manual steps above already do), **never** `pip install
--break-system-packages` against the system interpreter.

## Config changes require a restart

The daemon reads `config.yaml` and the project list once at startup. Editing the file,
or adding and removing projects, has no effect on a running daemon until it is
restarted (`Ctrl+C` and start again, or `systemctl --user restart systemlens`).

## Seeing why an analysis failed

A failed analysis prints one line (`analysis failed for project=…: <error>`). Run
`agent start --verbose` or `agent up --verbose` for full tracebacks and per-signal
decisions.

## Uninstalling

```bash
agent service uninstall       # if you installed the service
rm -rf .venv
rm -rf ~/.systemlens          # deletes all registered projects, history, and config
```

## See also

- [docs/CAPABILITIES.md](docs/CAPABILITIES.md) — exactly what SystemLens can and
  can't detect, and the correlation rules behind it.
- `agent --help` / `agent <command> --help` — full CLI reference.
