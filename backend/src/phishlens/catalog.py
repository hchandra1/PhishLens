"""Loads signals.toml and builds Signals from it, so weights live in one tunable file."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

from phishlens.models import Evidence, Severity, Signal


@dataclass(frozen=True)
class SignalSpec:
    severity: Severity
    weight: float
    reason: str


@cache
def load_catalog() -> dict[str, SignalSpec]:
    raw = tomllib.loads(files("phishlens").joinpath("signals.toml").read_text("utf-8"))
    return {
        signal_id: SignalSpec(Severity(spec["severity"]), float(spec["weight"]), spec["reason"])
        for signal_id, spec in raw.items()
    }


def make_signal(
    analyzer: str, signal_id: str, explanation: str, evidence: list[Evidence]
) -> Signal:
    spec = load_catalog()[signal_id]
    return Signal(
        analyzer=analyzer,
        id=signal_id,
        severity=spec.severity,
        weight=spec.weight,
        evidence=evidence,
        explanation=explanation,
    )
