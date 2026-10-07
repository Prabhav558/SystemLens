"""Local dashboard (`agent serve`): read-only view of this machine's
findings, straight from the project SQLite files. It has no login, so it
binds to localhost by default — for a dashboard reachable from elsewhere,
use the central server (`agent central serve`), which authenticates.

The page is rendered on the server with every value HTML-escaped, and is
served with a policy that allows no scripts at all.
"""
from __future__ import annotations

import html
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from systemlens.config import AgentConfig
from systemlens.core.lock import running_pid
from systemlens.memory.store import ProjectStore
from systemlens.projects.registry import ProjectRegistry

_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

_STYLE = """
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f1115;color:#e6e8ec}
header{padding:16px 24px;border-bottom:1px solid #262b38;display:flex;justify-content:space-between}
h1{font-size:16px;margin:0} .muted{color:#8a90a2;font-size:13px} main{max-width:1100px;margin:0 auto;padding:24px}
.f{background:#161922;border:1px solid #262b38;border-left:3px solid #6b7180;border-radius:8px;padding:12px 16px;margin-bottom:10px;font-size:13px;line-height:1.5}
.root_cause_identified{border-left-color:#ef5b5b}.probable_cause{border-left-color:#e0b84b}
.top{display:flex;justify-content:space-between;gap:12px} .fp{font-family:monospace;color:#8a90a2;font-size:11px}
.l{color:#8a90a2;margin-right:6px} .ok{color:#5bd68a} .bad{color:#ef5b5b}
"""


def _recent(config: AgentConfig, registry: ProjectRegistry, since_hours: float, limit: int) -> list[dict]:
    rows: list[dict] = []
    for project in registry.all():
        db_path = config.home / "projects" / project.name / "state.db"
        if not db_path.exists():
            continue
        store = ProjectStore(db_path)
        try:
            for r in store.recent_incidents(since=time.time() - since_hours * 3600, limit=limit):
                row = dict(r)
                row.pop("analysis_json", None)
                rows.append({"project": project.name, **row})
        finally:
            store.close()
    return sorted(rows, key=lambda r: r["created_at"], reverse=True)[:limit]


def build_app(config: AgentConfig) -> FastAPI:
    app = FastAPI(title="SystemLens")

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "daemon_pid": running_pid(config.home)}

    @app.get("/projects")
    def projects():
        return [{"name": p.name, "root": str(p.root), "enabled": p.enabled}
                for p in ProjectRegistry(config).all()]

    @app.get("/findings")
    def findings(since_hours: float = 24, limit: int = 100):
        return _recent(config, ProjectRegistry(config), since_hours, limit)

    @app.get("/projects/{name}/findings")
    def project_findings(name: str, since_hours: float = 24, limit: int = 100):
        registry = ProjectRegistry(config)
        if registry.get(name) is None:
            raise HTTPException(404, f"unknown project: {name}")
        return [r for r in _recent(config, registry, since_hours, limit) if r["project"] == name]

    @app.get("/", response_class=HTMLResponse)
    def dashboard(since_hours: float = 24):
        e = html.escape
        registry = ProjectRegistry(config)
        pid = running_pid(config.home)
        cards = []
        for r in _recent(config, registry, since_hours, 100):
            verdict = r["verdict"] if r["verdict"] in ("root_cause_identified", "probable_cause") else ""
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))
            confidence = f"{r['confidence']:.2f}" if r["confidence"] is not None else "—"
            cards.append(
                f'<div class="f {verdict}"><div class="top"><span><b>{e(r["project"])}</b> '
                f'<span class="fp">{e(r["fingerprint"])}</span></span><span class="muted">{e(when)}</span></div>'
                f'<div><span class="l">verdict:</span>{e(str(r["verdict"]).replace("_", " "))} '
                f'<span class="l">&nbsp;confidence:</span>{e(confidence)}</div>'
                f'<div><span class="l">component:</span>{e(r["affected_component"] or "—")}</div>'
                f'<div><span class="l">root cause:</span>{e(r["root_cause"] or "")}</div>'
                f'<div><span class="l">fix:</span>{e(r["fix_suggestion"] or "—")}</div></div>')
        state = (f'<span class="ok">daemon running (pid {pid})</span>' if pid
                 else '<span class="bad">daemon not running</span>')
        names = ", ".join(e(p.name) for p in registry.all()) or "none registered"
        body = "".join(cards) or '<p class="muted">No findings in this window.</p>'
        return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<meta http-equiv="refresh" content="15"><title>SystemLens</title><style>{_STYLE}</style></head>'
                f'<body><header><h1>SystemLens</h1><span class="muted">{state}</span></header>'
                f'<main><p class="muted">Projects: {names} · last {e(f"{since_hours:g}")}h · refreshes every 15s</p>'
                f'{body}</main></body></html>')

    return app
