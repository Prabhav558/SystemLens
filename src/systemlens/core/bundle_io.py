"""EvidenceBundle <-> JSON. A recorded bundle is exactly what an analysis
saw, so it can be replayed later: by `agent eval` to score accuracy, by
`agent explain` to show the evidence, and by `agent investigate`.
"""
from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from typing import Optional

from systemlens.core.models import (
    Analysis, CandidateCause, ContainerState, EvidenceBundle, LogRecord, PriorIncident,
    Severity, Signal,
)


def bundle_to_dict(bundle: EvidenceBundle) -> dict:
    return dataclasses.asdict(bundle)


def _record(d: dict) -> LogRecord:
    return LogRecord(**{**d, "severity": Severity(d["severity"])})


def bundle_from_dict(d: dict) -> EvidenceBundle:
    sig = d["signal"]
    return EvidenceBundle(
        project=d["project"],
        signal=Signal(record=_record(sig["record"]), template=sig["template"],
                      fingerprint=sig["fingerprint"], category=sig["category"],
                      hints=sig.get("hints") or {}),
        occurrences=d.get("occurrences", 1),
        log_window=[_record(r) for r in d.get("log_window", [])],
        containers=[ContainerState(**c) for c in d.get("containers", [])],
        container_logs=d.get("container_logs") or {},
        candidates=[CandidateCause(**c) for c in d.get("candidates", [])],
        prior=PriorIncident(**d["prior"]) if d.get("prior") else None,
        similar=[PriorIncident(**p) for p in d.get("similar", [])],
        docker_available=d.get("docker_available", True),
        mapping_confidence=d.get("mapping_confidence", "high"),
        created_at=d.get("created_at", time.time()),
        max_evidence_chars=d.get("max_evidence_chars"),
    )


def save_recording(directory: Path, bundle: EvidenceBundle, analysis: Analysis,
                   provider: str, model: str) -> Path:
    """Keep the latest bundle per fingerprint (bounded by distinct issues)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{bundle.signal.fingerprint}.json"
    path.write_text(json.dumps({
        "recorded_at": time.time(), "provider": provider, "model": model,
        "analysis": json.loads(analysis.model_dump_json()),
        "bundle": bundle_to_dict(bundle),
    }, indent=1))
    return path


def load_recording(path: Path) -> tuple[EvidenceBundle, Optional[dict]]:
    data = json.loads(path.read_text())
    return bundle_from_dict(data["bundle"]), data.get("analysis")


def prune_recordings(directory: Path, retention_days: int) -> int:
    if not directory.is_dir():
        return 0
    cutoff, removed = time.time() - retention_days * 86400, 0
    for f in directory.glob("*.json"):
        if f.stat().st_mtime < cutoff:
            f.unlink()
            removed += 1
    return removed
