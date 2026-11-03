# Deploying SystemLens

There are two things to deploy, and most people only need the first.

| Piece | What it is | Where it runs |
|---|---|---|
| **Agent** | Watches projects, analyses failures, stores findings | On each machine that runs your containers. It needs that machine's Docker socket, so it cannot run anywhere else. |
| **Central server** (optional) | Collects findings pushed by one or more agents; serves a browser dashboard behind API keys | Anywhere agents can reach over HTTPS |

## 1. Agent as a background service

```bash
agent service install --enable
journalctl --user -u systemlens -f
```

This writes a systemd user unit that runs `agent start` and restarts it on failure.
A service does not inherit your shell's environment: put secrets in
`~/.systemlens/env` (created with mode 600), one `KEY=value` per line:

```
GROQ_API_KEY=...
SYSTEMLENS_SLACK_WEBHOOK=https://hooks.slack.com/...
SYSTEMLENS_HTTP_TOKEN=sla_...
```

To keep it running after you log out: `loginctl enable-linger $USER`.

Registering or removing projects (`agent up`, `agent remove-project`) takes effect on
the running service within a few seconds. Changes to `config.yaml` need
`systemctl --user restart systemlens`.

## 2. Agent in a container

```bash
PROJECT_DIR=/home/me/myapp docker compose -f deploy/docker-compose.agent.yml up -d --build
docker compose -f deploy/docker-compose.agent.yml exec agent systemlens add-project /home/me/myapp
```

Read the comments in `deploy/docker-compose.agent.yml` first. The container needs the
Docker socket, and access to that socket is equivalent to root on the host. The file
mounts it read-only; for stricter isolation, put a socket proxy that only permits GET
requests in front of it and set `docker_socket` in `config.yaml` to the proxy.

## 3. Central server

The server speaks plain HTTP. For anything other than localhost it must sit behind a
reverse proxy that terminates TLS, because API keys travel in a header.

```bash
export SYSTEMLENS_DOMAIN=lens.example.com
docker compose -f deploy/docker-compose.central.yml up -d --build
docker compose -f deploy/docker-compose.central.yml exec central systemlens central register-agent my-laptop
```

Caddy obtains the certificate. `register-agent` prints an API key once; only its hash
is stored. On the machine running the agent:

```yaml
# ~/.systemlens/config.yaml
sinks:
  http_enabled: true
  http_url: https://lens.example.com/ingest/findings
```
```bash
export SYSTEMLENS_HTTP_TOKEN=sla_...      # or put it in ~/.systemlens/env for the service
agent central backfill                    # optional: send findings made before this
```

Open `https://lens.example.com/` and paste the same key to see that agent's findings.

Without Docker: `agent central serve --host 127.0.0.1` behind nginx or Caddy on the
same host. Pass `--forwarded-allow-ips` with your proxy's address so per-client
throttling sees real client addresses.

### What the server does and does not protect

- Each agent key can push findings and read **only its own**.
- Keys are random 256-bit tokens, stored hashed. `agent central revoke-agent <id>`
  disables one immediately; its findings are kept.
- Twenty rejected credentials from one address within a minute are answered with 429.
- Request bodies over 256 KB are rejected. Findings older than `retention.days` are
  pruned at startup.
- The dashboard never renders finding text as HTML and is served with a
  Content-Security-Policy that permits only its own script and stylesheet.
- Pushes that fail are kept in the agent's outbox and retried; a push is stored once
  even if it is delivered twice.
- **Not provided:** user accounts, per-user permissions, or TLS. Anyone holding an
  agent's key can read that agent's findings.
- Only the analysis is pushed (root cause, component, fix, quoted evidence). Raw logs
  and the evidence bundle stay on the agent's machine. Secrets are redacted before
  analysis, by pattern; review `docs/CAPABILITIES.md` for the limits of that.

### Remote registration

Setting `SYSTEMLENS_CENTRAL_ADMIN_KEY` on the server enables `POST /agents/register`
(with that key as the bearer token), for provisioning agents without shell access to
the server. Leave it unset if you do not need it; the endpoint then answers 503.

## 4. Notifications

Set any of these in the agent's environment (or `~/.systemlens/env`):

| Variable | Target |
|---|---|
| `SYSTEMLENS_SLACK_WEBHOOK` | Slack incoming webhook |
| `SYSTEMLENS_DISCORD_WEBHOOK` | Discord webhook |
| `SYSTEMLENS_WEBHOOK_URL` | Any URL; receives the finding as JSON |

`notify.desktop: true` adds desktop popups where `notify-send` exists. Check with
`agent notify-test`. By default only findings with a cause and confidence of at least
0.5 are sent; `notify.daily_digest_at: "09:00"` adds a daily summary.

## 5. MCP

```bash
pip install "systemlens[mcp]"
claude mcp add systemlens -- agent mcp        # Claude Code; other clients: command `agent mcp`
```

Tools: `list_projects`, `list_findings`, `get_finding`, `resolve`, `digest`. The server
reads the local data directory and does not need the daemon running.

## 6. Releasing the package

```bash
python -m build                 # dist/systemlens-<version>-py3-none-any.whl and .tar.gz
twine upload dist/*             # needs your PyPI credentials
```

After that, `pipx install "systemlens[groq]"` works anywhere. The name `systemlens`
must be available on PyPI under your account; this has not been checked.

## Upgrading

Data lives in `~/.systemlens` (or `$SYSTEMLENS_HOME`). Databases are migrated in place
on first start of a new version. Back the directory up before upgrading if the history
matters to you.
