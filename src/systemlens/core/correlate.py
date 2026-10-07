"""The engine. Every rule here is deterministic Python — no LLM involved.
The LLM (llm/) only ever ranks and narrates what these rules produce; it
never discovers a candidate cause on its own. Keeping this boundary strict
is what keeps the tool honest and cheap.

Rules:
  R1 connection_refused/timeout/dns -> resolve host:port to a container
  R2 a container exited within the correlation window
  R3 OOM kill
  R4 container health check failing
  R5 upstream compose depends_on is down/unhealthy
  R6 fingerprint has a stored resolution

Scoping: R2-R5 describe container state, which is true project-wide. A fact
is only offered as a *candidate cause* when its container is linked to the
signal — the container that logged it, the container it was trying to
reach, or a compose dependency of either. Every other fact is still
reported, but marked `scoped=False` (co-occurring), capped in confidence,
and never enough on its own to support a conclusion (see core/grounding.py).
Unscoped facts being presented as candidates is what produced confident,
wrong diagnoses such as blaming a database exit for an unrelated service's
hard-coded health check failure.
"""
from __future__ import annotations

import re
from typing import Optional

from systemlens.containers.mapping import build_dependency_graph
from systemlens.core.models import CandidateCause, ContainerState, EvidenceBundle, Signal


def _find_container_by_alias(host: str, containers: list[ContainerState]) -> Optional[ContainerState]:
    for c in containers:
        if host == c.name or host == c.compose_service or host in c.aliases:
            return c
    for c in containers:
        if host in c.ip_addresses:
            return c
    return None


def rule_r1_connection_target(signal: Signal, containers: list[ContainerState]) -> Optional[CandidateCause]:
    if signal.category not in ("connection_refused", "timeout", "dns_failure"):
        return None
    host = signal.hints.get("host")
    if not host:
        return None
    target = _find_container_by_alias(host, containers)
    if target is None:
        return None
    state_desc = "running" if target.running else f"{target.status} (exit {target.exit_code})"
    return CandidateCause(
        rule_id="R1", component=target.name,
        summary=f"'{host}' resolves to container '{target.name}', currently {state_desc}",
        confidence=0.85 if not target.running else 0.35,
        evidence=[signal.record.first_line,
                  f"{target.name} status={target.status} exit_code={target.exit_code}"],
        meta={"container_id": target.id},
    )


EXIT_SKEW_SECONDS = 5.0


def rule_r2_recent_exit(signal: Signal, containers: list[ContainerState], window_seconds: int) -> list[CandidateCause]:
    out: list[CandidateCause] = []
    incident_ts = signal.record.when
    for c in containers:
        age = c.age_of_death(now=incident_ts)
        if age is not None and -EXIT_SKEW_SECONDS <= age <= window_seconds:
            age = max(age, 0.0)
            out.append(CandidateCause(
                rule_id="R2", component=c.name,
                summary=f"container '{c.name}' exited {age:.0f}s before this error "
                        f"(exit_code={c.exit_code})",
                confidence=max(0.4, 0.9 - age / window_seconds * 0.5),
                evidence=[f"{c.name} exited at t-{age:.0f}s, exit_code={c.exit_code}"],
                meta={"container_id": c.id, "age": age},
            ))
    return out


def rule_r3_oom(containers: list[ContainerState]) -> list[CandidateCause]:
    out = []
    for c in containers:
        if c.oom_killed:
            out.append(CandidateCause(
                rule_id="R3", component=c.name,
                summary=f"container '{c.name}' was OOM-killed",
                confidence=0.9,
                evidence=[f"{c.name} OOMKilled=true exit_code={c.exit_code} memory_limit={c.memory_limit}"],
                meta={"container_id": c.id},
            ))
        elif not c.running and c.exit_code == 137:
            # 137 = SIGKILL. Often the OOM killer, but also `docker kill` or a
            # stop timeout — Docker did not confirm an OOM, so say so.
            out.append(CandidateCause(
                rule_id="R3", component=c.name,
                summary=f"container '{c.name}' was killed with SIGKILL (exit 137); "
                        f"an OOM kill is possible but not confirmed by Docker",
                confidence=0.5,
                evidence=[f"{c.name} exit_code=137 OOMKilled=false memory_limit={c.memory_limit}"],
                meta={"container_id": c.id},
            ))
    return out


def rule_r4_health(containers: list[ContainerState]) -> list[CandidateCause]:
    out = []
    for c in containers:
        if c.health == "unhealthy":
            out.append(CandidateCause(
                rule_id="R4", component=c.name,
                summary=f"container '{c.name}' health check is failing",
                confidence=0.75,
                evidence=[f"{c.name} health=unhealthy"] + c.health_log[-3:],
                meta={"container_id": c.id},
            ))
        elif c.health == "starting":
            # Still in its health-check grace period — weaker evidence than
            # a confirmed failure, but relevant context for a slow-starting
            # or flapping service, so surface it at lower confidence.
            out.append(CandidateCause(
                rule_id="R4", component=c.name,
                summary=f"container '{c.name}' has not passed its health check yet (still starting)",
                confidence=0.35,
                evidence=[f"{c.name} health=starting"] + c.health_log[-3:],
                meta={"container_id": c.id},
            ))
    return out


def rule_r5_dependency_chain(containers: list[ContainerState]) -> list[CandidateCause]:
    graph = build_dependency_graph(containers)
    by_service = {c.compose_service or c.name: c for c in containers}
    out = []
    for service, deps in graph.items():
        me = by_service.get(service)
        if me is None or not me.running:
            continue
        for dep in deps:
            dep_state = by_service.get(dep)
            if dep_state and (not dep_state.running or dep_state.health == "unhealthy"):
                out.append(CandidateCause(
                    rule_id="R5", component=dep_state.name,
                    summary=f"'{service}' depends on '{dep}', which is "
                            f"{'unhealthy' if dep_state.health == 'unhealthy' else dep_state.status}",
                    confidence=0.6,
                    evidence=[f"compose depends_on: {service} -> {dep}",
                              f"{dep}: status={dep_state.status} health={dep_state.health}"],
                    meta={"container_id": dep_state.id},
                ))
    return out


UNSCOPED_CONFIDENCE_CAP = 0.3


def resolve_origin(signal: Signal, containers: list[ContainerState]) -> Optional[ContainerState]:
    """The container that emitted the triggering record, when the source knows it."""
    name = signal.record.container
    if not name:
        return None
    for c in containers:
        if name in (c.name, c.compose_service):
            return c
    return None


def _dependency_closure(start: ContainerState, containers: list[ContainerState]) -> set[str]:
    """Ids of every container `start` transitively depends on (compose depends_on)."""
    graph = build_dependency_graph(containers)
    by_service = {c.compose_service or c.name: c for c in containers}
    seen: set[str] = set()
    stack = list(graph.get(start.compose_service or start.name, []))
    while stack:
        dep = by_service.get(stack.pop())
        if dep is None or dep.id in seen:
            continue
        seen.add(dep.id)
        stack.extend(graph.get(dep.compose_service or dep.name, []))
    return seen


# A dependency being down can explain a failed connection, a failed health
# check, a crash, or an error we could not classify. It does not explain a
# KeyError, a missing file, a permission error or an OOM kill, so for those
# categories a dependency's state is only co-occurring.
_DEPENDENCY_EXPLAINS = frozenset({
    "connection_refused", "timeout", "dns_failure", "health_check", "container_exit", "generic",
})


def mentions(container: ContainerState, text: str) -> bool:
    """True if `text` (lower-cased) names the container or its compose service."""
    names = [n for n in (container.name, container.compose_service) if n and len(n) >= 2]
    return any(re.search(rf"(?<![\w-]){re.escape(n.lower())}(?![\w-])", text) for n in names)


def linked_container_ids(signal: Signal, containers: list[ContainerState]) -> Optional[set[str]]:
    """Containers with an established link to this signal: its origin, its
    connection target, any container the signal names, and — where a
    dependency could explain this kind of failure — their compose
    dependencies. None means there is no origin, target or named container,
    so nothing can be linked.
    """
    origin = resolve_origin(signal, containers)
    target = None
    host = signal.hints.get("host")
    if host and signal.category in ("connection_refused", "timeout", "dns_failure"):
        target = _find_container_by_alias(host, containers)
    text = signal.record.raw.lower()
    anchors = {c.id: c for c in containers if mentions(c, text)}
    for c in (origin, target):
        if c is not None:
            anchors[c.id] = c
    if not anchors:
        return None
    linked = set(anchors)
    if signal.category in _DEPENDENCY_EXPLAINS:
        for c in anchors.values():
            linked |= _dependency_closure(c, containers)
    return linked


def correlate(bundle: EvidenceBundle, window_seconds: int) -> list[CandidateCause]:
    """Run all rules. Scoped candidates come first, each group sorted by
    confidence. Container facts with no link to the signal are kept, but as
    `scoped=False` with capped confidence.
    """
    signal = bundle.signal
    candidates: list[CandidateCause] = []

    if not bundle.docker_available:
        # Docker layer is down: we can still say something from logs alone.
        candidates.append(CandidateCause(
            rule_id="R0", component="unknown",
            summary="Docker is unavailable; correlation is log-only for this incident",
            confidence=0.1, evidence=[signal.record.first_line],
        ))
        return candidates

    r1 = rule_r1_connection_target(signal, bundle.containers)
    if r1:
        candidates.append(r1)

    facts = rule_r2_recent_exit(signal, bundle.containers, window_seconds)
    facts += rule_r3_oom(bundle.containers)
    facts += rule_r4_health(bundle.containers)
    facts += rule_r5_dependency_chain(bundle.containers)

    linked = linked_container_ids(signal, bundle.containers)
    for fact in facts:
        # every fact is about one container (for R5, the dependency that is down)
        if linked is None or fact.meta.get("container_id") not in linked:
            fact.scoped = False
            fact.confidence = min(fact.confidence, UNSCOPED_CONFIDENCE_CAP)
    candidates += facts

    if bundle.prior and bundle.prior.resolution:
        candidates.append(CandidateCause(
            rule_id="R6", component=bundle.project,
            summary="This exact fingerprint has a stored resolution from a prior incident",
            confidence=0.95,
            evidence=[f"prior resolution: {bundle.prior.resolution}"],
            meta={"prior_fingerprint": bundle.prior.fingerprint},
        ))

    candidates.sort(key=lambda c: (c.scoped, c.confidence), reverse=True)
    return candidates
