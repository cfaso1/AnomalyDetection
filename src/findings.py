"""
Finding dataclass and helpers.

A Finding is the unit of output of the redesigned detector: a single
developer-actionable anomaly with full context. Findings are produced by:
  - the rule engine (rules.py + rule_engine.py), and optionally
  - supporting evidence from the supervised classifier (Engine B attention).

Each Finding carries enough context for a developer to triage without
re-reading the source log.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

from .rules import severity_rank


@dataclass
class Finding:
    """A single developer-actionable anomaly detection."""

    rule_name: str                       # e.g. 'deauth_reason_07_class3_frame'
    category: str                        # e.g. '802.11 Protocol Violation'
    severity: str                        # CRITICAL / HIGH / MEDIUM / LOW
    description: str                     # one-line headline

    # Where in the file the anomaly occurred.
    line_number: int                     # 1-indexed
    timestamp: str                       # original timestamp text
    elapsed_ms: int                      # ms since file start (0 if unknown)
    component: str                       # log component tag (e.g. SSPWIFI)

    # The actual trigger line(s).
    trigger_line: str                    # the matched raw line
    # Lines before/after for context.
    context_before: list[str] = field(default_factory=list)
    context_after:  list[str] = field(default_factory=list)

    # For burst-style findings, additional lines included in the burst.
    burst_line_numbers: list[int] = field(default_factory=list)
    burst_size: int = 1

    # Supporting evidence (optional).
    classifier_attention: Optional[float] = None  # 0..1 if Engine B agreed
    rare_template: bool = False                   # template unseen in normal corpus

    # Computed at aggregation time.
    actionability_score: float = 0.0     # 0..1 ranking score


def actionability(finding: Finding) -> float:
    """
    Compute a 0..1 actionability score combining:
      - severity (dominant)
      - burst size (storms are more confident than single hits)
      - classifier attention (corroborating ML evidence)
      - rare-template flag (additional novelty signal)
    """
    sev = severity_rank(finding.severity) / 4.0          # 0.25 .. 1.0
    burst_boost = min(0.15, (finding.burst_size - 1) * 0.02)
    cls_boost   = (finding.classifier_attention or 0.0) * 0.10
    rare_boost  = 0.05 if finding.rare_template else 0.0
    return min(1.0, sev + burst_boost + cls_boost + rare_boost)


def finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    return d


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by actionability desc, then severity desc, then line asc."""
    for f in findings:
        f.actionability_score = actionability(f)
    return sorted(
        findings,
        key=lambda f: (-f.actionability_score,
                       -severity_rank(f.severity),
                       f.line_number),
    )
