"""Signals -> score -> label. All numbers come from scoring.toml and signals.toml."""

from __future__ import annotations

import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files

from phishlens.catalog import load_catalog
from phishlens.models import Label, Severity, Signal

_LABEL_RANK = {Label.SAFE: 0, Label.SUSPICIOUS: 1, Label.PHISHING: 2}


@dataclass(frozen=True)
class Override:
    label: Label
    signals: frozenset[str]
    reason: str


@dataclass(frozen=True)
class ScoringConfig:
    suspicious_threshold: float
    phishing_threshold: float
    ignore_trust_when_high_severity: bool
    overrides: tuple[Override, ...]
    analyzer_caps: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 < self.suspicious_threshold < self.phishing_threshold <= 100:
            raise ValueError("thresholds must satisfy 0 < suspicious < phishing <= 100")
        unknown = {s for o in self.overrides for s in o.signals} - set(load_catalog())
        if unknown:
            raise ValueError(f"overrides reference unknown signals: {sorted(unknown)}")

    def threshold(self, label: Label) -> float:
        return {Label.SAFE: 0, Label.SUSPICIOUS: self.suspicious_threshold,
                Label.PHISHING: self.phishing_threshold}[label]  # fmt: skip


@cache
def load_scoring_config() -> ScoringConfig:
    raw = tomllib.loads(files("phishlens").joinpath("scoring.toml").read_text("utf-8"))
    return ScoringConfig(
        suspicious_threshold=float(raw["thresholds"]["suspicious"]),
        phishing_threshold=float(raw["thresholds"]["phishing"]),
        ignore_trust_when_high_severity=bool(raw["trust"]["ignore_when_high_severity"]),
        overrides=tuple(
            Override(Label(o["label"]), frozenset(o["signals"]), o["reason"])
            for o in raw.get("overrides", [])
        ),
        analyzer_caps={k: float(v) for k, v in raw.get("analyzer_caps", {}).items()},
    )


@dataclass(frozen=True)
class Score:
    label: Label
    score: float
    override: str | None
    counted: list[Signal]
    """Signals that contributed to the score (trust signals may be dropped)."""


def score_signals(signals: list[Signal], config: ScoringConfig | None = None) -> Score:
    config = config or load_scoring_config()
    has_high = any(s.severity == Severity.HIGH for s in signals)
    counted = [
        s
        for s in signals
        if s.weight >= 0 or not (has_high and config.ignore_trust_when_high_severity)
    ]
    score = min(100.0, max(0.0, _capped_total(counted, config.analyzer_caps)))

    label = Label.SAFE
    for candidate in (Label.PHISHING, Label.SUSPICIOUS):
        if score >= config.threshold(candidate):
            label = candidate
            break

    override = None
    ids = {s.id for s in signals}
    for rule in config.overrides:
        if ids & rule.signals and _LABEL_RANK[rule.label] > _LABEL_RANK[label]:
            label, override = rule.label, rule.reason
            # Keep the number consistent with the label the user sees.
            score = max(score, config.threshold(rule.label))
    return Score(label=label, score=round(score, 1), override=override, counted=counted)


def _capped_total(signals: list[Signal], caps: dict[str, float]) -> float:
    per_analyzer: dict[str, float] = defaultdict(float)
    for signal in signals:
        per_analyzer[signal.analyzer] += signal.weight
    return sum(
        min(total, caps[name]) if name in caps else total for name, total in per_analyzer.items()
    )
