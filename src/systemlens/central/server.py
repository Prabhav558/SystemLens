"""Central server: the receiving end of sinks.HttpSink. One or more local
agent daemons push findings here over HTTPS, each authenticated by its own
per-agent Bearer key; the browser dashboard reads back with that same key,
scoped to that agent's own findings only — no cross-agent visibility.

Registration (minting a new agent's key) is a separate, higher-privilege
action gated by a single shared admin key, so pushing/viewing findings and
creating new agents are deliberately different trust levels.
"""
from __future__ import annotations

import hmac
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from systemlens.central.auth import generate_api_key
from systemlens.central.store import CentralStore

STATIC_DIR = Path(__file__).parent / "static"


class RegisterAgentRequest(BaseModel):
    name: str


class IngestFindingRequest(BaseModel):
    project: str
    fingerprint: str
    analysis: dict
    provider: Optional[str] = None
    model: Optional[str] = None
    created_at: float


def _extract_bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing or malformed Authorization header")
    return authorization.split(" ", 1)[1].strip()


# The dashboard loads only its own script and stylesheet. Finding text comes
# from logs, so the page must never be able to execute anything injected
# through it; this is the backstop behind the DOM-only rendering in
# static/dashboard.js.
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


MAX_BODY_BYTES = 256 * 1024          # a finding is a few KB; nothing legitimate is larger
MAX_AUTH_FAILURES = 20               # per client address, per window
AUTH_WINDOW_SECONDS = 60.0


class _AuthThrottle:
    """Slows down guessing of keys: after too many rejected credentials from
    one address, further attempts get 429 until the window passes.
    """
    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}

    def blocked(self, client: str) -> bool:
        cutoff = time.time() - AUTH_WINDOW_SECONDS
        recent = [t for t in self._failures.get(client, []) if t >= cutoff]
        self._failures[client] = recent
        return len(recent) >= MAX_AUTH_FAILURES

    def record(self, client: str) -> None:
        self._failures.setdefault(client, []).append(time.time())
        if len(self._failures) > 10_000:      # bound memory under a wide scan
            self._failures.clear()


def build_central_app(db_path: Path, admin_key_env: str = "SYSTEMLENS_CENTRAL_ADMIN_KEY",
                      retention_days: Optional[int] = None) -> FastAPI:
    app = FastAPI(title="SystemLens Central", docs_url=None, redoc_url=None, openapi_url=None)
    throttle = _AuthThrottle()
    store = CentralStore(db_path)
    if retention_days:
        store.prune(retention_days)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        if throttle.blocked(client):
            return JSONResponse({"detail": "too many failed authentication attempts"}, status_code=429)
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        response = await call_next(request)
        if response.status_code == 401:
            throttle.record(client)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def require_agent(authorization: Optional[str] = Header(None)):
        key = _extract_bearer(authorization)
        agent = store.agent_by_key(key)
        if agent is None:
            raise HTTPException(401, "invalid API key")
        return agent

    def require_admin(authorization: Optional[str] = Header(None)):
        key = _extract_bearer(authorization)
        admin_key = os.environ.get(admin_key_env)
        if not admin_key:
            raise HTTPException(503, f"${admin_key_env} is not set on the server")
        if not hmac.compare_digest(key.encode(), admin_key.encode()):
            raise HTTPException(401, "invalid admin key")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/agents/register", dependencies=[Depends(require_admin)])
    def register_agent(req: RegisterAgentRequest):
        api_key = generate_api_key()
        agent_id = store.register_agent(req.name, api_key)
        # api_key is returned exactly once — only its hash is ever stored.
        return {"agent_id": agent_id, "name": req.name, "api_key": api_key}

    @app.post("/ingest/findings")
    def ingest_finding(req: IngestFindingRequest, agent=Depends(require_agent)):
        finding_id = store.record_finding(
            agent_id=agent["id"], project=req.project, fingerprint=req.fingerprint,
            analysis=req.analysis, provider=req.provider, model=req.model,
            created_at=req.created_at,
        )
        return {"id": finding_id, "status": "recorded" if finding_id else "duplicate"}

    @app.get("/findings")
    def list_findings(project: Optional[str] = None, since_hours: Optional[float] = None,
                       limit: int = 200, agent=Depends(require_agent)):
        since = time.time() - since_hours * 3600 if since_hours else None
        rows = store.findings_for_agent(agent["id"], project=project, since=since, limit=limit)
        return [dict(r) for r in rows]

    @app.get("/agents/me")
    def whoami(agent=Depends(require_agent)):
        return {"id": agent["id"], "name": agent["name"], "created_at": agent["created_at"]}

    @app.get("/")
    def dashboard():
        return FileResponse(STATIC_DIR / "dashboard.html")

    return app
