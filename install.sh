#!/usr/bin/env bash
# SystemLens plug-and-play installer.
#
# Default (no flags): sets up the venv + package, then hands off to the
# interactive `agent init` picker. Safe to re-run — every step is idempotent.
#
# Non-interactive: pass --provider to skip the interactive picker entirely
# and write config.yaml directly, e.g. for CI or scripted setup:
#   ./install.sh --provider groq --model openai/gpt-oss-120b
#   ./install.sh --provider ollama --model llama3.1
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

PROVIDER=""
MODEL=""
OLLAMA_URL="http://localhost:11434"
GROQ_KEY_ENV="GROQ_API_KEY"
EXTRAS="groq,api,faiss"
SKIP_DOCTOR=false

usage() {
    cat <<EOF
Usage: ./install.sh [options]

  --provider {ollama|groq}   Skip the interactive picker, write config.yaml directly
  --model MODEL              Model name (default: llama3.1 for ollama, openai/gpt-oss-120b for groq)
  --ollama-url URL           Ollama base URL (default: http://localhost:11434)
  --groq-key-env NAME        Env var name holding your Groq key (default: GROQ_API_KEY)
  --extras LIST              pip extras to install (default: groq,api,faiss)
  --no-doctor                Skip the final 'agent doctor' check
  -h, --help                 Show this help

No flags: interactive setup (recommended for first-time use).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --provider) PROVIDER="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        --ollama-url) OLLAMA_URL="$2"; shift 2 ;;
        --groq-key-env) GROQ_KEY_ENV="$2"; shift 2 ;;
        --extras) EXTRAS="$2"; shift 2 ;;
        --no-doctor) SKIP_DOCTOR=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

info()  { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m!!\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m✓\033[0m %s\n' "$1"; }
die()   { printf '\033[1;31mERROR:\033[0m %s\n' "$1" >&2; exit 1; }

# -- 1. prerequisites ---------------------------------------------------
info "Checking prerequisites"

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.10+ first."
PY_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')"
[ "$PY_OK" = "1" ] || die "Python 3.10+ required, found $PY_VERSION."
ok "python3 $PY_VERSION"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ok "docker reachable"
else
    warn "docker not found or not reachable — SystemLens will still run, but container" \
         "correlation (the reason it exists) needs a working Docker daemon. On WSL, enable" \
         "Docker Desktop's WSL integration for this distro; see INSTALL.md."
fi

# -- 2. venv --------------------------------------------------------------
if [ -d "$REPO_DIR/.venv" ]; then
    ok "venv already exists at .venv — reusing it"
else
    info "Creating venv at .venv"
    python3 -m venv "$REPO_DIR/.venv"
fi

VENV_PY="$REPO_DIR/.venv/bin/python"
VENV_PIP="$REPO_DIR/.venv/bin/pip"

# -- 3. install -------------------------------------------------------------
info "Installing SystemLens (extras: $EXTRAS)"
"$VENV_PIP" install -q --upgrade pip
"$VENV_PIP" install -q -e ".[$EXTRAS]"
ok "installed into .venv"

AGENT_BIN="$REPO_DIR/.venv/bin/agent"

# -- 4. configure -----------------------------------------------------------
if [ -n "$PROVIDER" ]; then
    info "Writing config.yaml non-interactively (provider=$PROVIDER)"
    case "$PROVIDER" in
        ollama) DEFAULT_MODEL="llama3.1" ;;
        groq)   DEFAULT_MODEL="openai/gpt-oss-120b" ;;
        *) die "--provider must be 'ollama' or 'groq', got: $PROVIDER" ;;
    esac
    MODEL="${MODEL:-$DEFAULT_MODEL}"

    "$VENV_PY" - "$PROVIDER" "$MODEL" "$OLLAMA_URL" "$GROQ_KEY_ENV" <<'PYEOF'
import sys
from systemlens.config import AgentConfig, ProviderConfig

provider, model, ollama_url, groq_key_env = sys.argv[1:5]
base_url = ollama_url if provider == "ollama" else None
api_key_env = groq_key_env if provider == "groq" else ""

config = AgentConfig(llm=ProviderConfig(provider=provider, model=model,
                                         api_key_env=api_key_env, base_url=base_url))
config.save()
print(f"wrote {config.config_path}")
PYEOF

    if [ "$PROVIDER" = "groq" ] && [ -z "${!GROQ_KEY_ENV:-}" ]; then
        warn "\$$GROQ_KEY_ENV is not set in this shell — export it before running 'agent start':"
        warn "  export $GROQ_KEY_ENV=your-key-here"
    fi
else
    info "Launching interactive setup (pick a provider, model, credentials)"
    "$AGENT_BIN" init
fi

# -- 5. doctor --------------------------------------------------------------
if [ "$SKIP_DOCTOR" = false ]; then
    info "Running agent doctor"
    "$AGENT_BIN" doctor || warn "doctor reported issues above — fix them before 'agent start'"
fi

# -- 6. done ------------------------------------------------------------
echo
ok "Setup complete."
cat <<EOF

Next steps:
  source .venv/bin/activate
  cd /path/to/your/compose/project
  agent up                      # registers the project and starts watching it

See INSTALL.md for the full walkthrough, and docs/CAPABILITIES.md for what
SystemLens can and can't detect.
EOF
