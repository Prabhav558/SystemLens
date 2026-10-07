"""Digest: what appeared, what keeps recurring, what got resolved. The
numbers come straight from SQLite, so the digest works with no LLM; an
optional one-paragraph narrative can be added on top.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from systemlens.memory.store import ProjectStore

DIGEST_SYSTEM = (
    "You summarise an operations digest for a developer in 3-4 plain sentences. Use only "
    "the numbers and items given. Lead with what most needs attention. Do not invent causes."
)


@dataclass(slots=True)
class Digest:
    since: float
    projects: dict[str, dict] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not any(p["new"] or p["recurring"] or p["resolved"] or p["verdicts"]
                       or p["failed_analyses"] or p["fixes"] for p in self.projects.values())


def build_digest(stores: dict[str, ProjectStore], since: float) -> Digest:
    return Digest(since, {name: store.summary(since) for name, store in stores.items()})


def _issue(row: dict) -> str:
    return f"{row['fingerprint']} [{row['category']}] ×{row['occurrences']}  {row['template'][:70]}"


def render_digest(digest: Digest) -> str:
    hours = max(1, round((time.time() - digest.since) / 3600))
    lines = [f"SystemLens digest — last {hours}h"]
    if digest.empty:
        return lines[0] + "\nNothing to report."
    for name, p in digest.projects.items():
        v = p["verdicts"]
        lines += ["", f"{name}",
                  f"  findings: {v.get('root_cause_identified', 0)} root cause, "
                  f"{v.get('probable_cause', 0)} probable, {v.get('insufficient_evidence', 0)} inconclusive"
                  + (f"; {p['failed_analyses']} analyses failed" if p["failed_analyses"] else "")]
        if p["new"]:
            lines.append(f"  new issues ({len(p['new'])}):")
            lines += [f"    {_issue(r)}" for r in p["new"][:5]]
        if p["recurring"]:
            lines.append(f"  still recurring ({len(p['recurring'])}):")
            lines += [f"    {_issue(r)}" for r in p["recurring"][:5]]
        if p["resolved"]:
            lines.append(f"  resolved ({len(p['resolved'])}):")
            lines += [f"    {r['fingerprint']} [{r['category']}]  {str(r['resolution'])[:70]}"
                      for r in p["resolved"][:5]]
        if p["fixes"]:
            f = p["fixes"]
            lines.append(f"  fixes: {f.get('verified', 0)} verified, {f.get('failed', 0)} failed, "
                         f"{f.get('pending', 0)} being verified")
    return "\n".join(lines)


async def narrate(llm, digest_text: str) -> str:
    return (await llm.complete_text(DIGEST_SYSTEM, digest_text)).strip()
