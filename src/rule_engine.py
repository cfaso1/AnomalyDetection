"""
Apply the curated bug-rule library to a parsed log file and return Findings.

This is the primary detection layer of the redesigned pipeline. It runs at
the *raw-line* level (not at the Drain-template level) because bug patterns
are precise regex matches, and we want exact line numbers + raw text for
the developer-facing output.

The supervised classifier (Engine B) and the rare-template detector remain
available as auxiliary evidence sources, contributed via
`findings_aggregator.attach_classifier_evidence()` etc.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .findings import Finding
from .rules import Rule, get_rules
from .parser import _LOG_LINE_RE as _PS_LINE_RE


def _read_lines(path: Path) -> list[str]:
    """Read all lines of a log file (lossless decode)."""
    # Try utf-8 first, fall back to latin-1 to never lose lines.
    try:
        with open(path, encoding='utf-8', errors='strict') as f:
            return f.read().splitlines()
    except UnicodeDecodeError:
        with open(path, encoding='latin-1') as f:
            return f.read().splitlines()


def _line_context(lines: list[str], idx: int, before: int, after: int
                  ) -> tuple[list[str], list[str]]:
    lo = max(0, idx - before)
    hi = min(len(lines), idx + after + 1)
    return lines[lo:idx], lines[idx + 1:hi]


def _extract_meta(line: str) -> tuple[str, int, str]:
    """
    Extract (timestamp_text, elapsed_ms, component) from a raw log line.
    Matches the same conventions used in src/parser.py.
    """
    import re
    ts_text = ''
    elapsed_ms = 0
    component = ''

    # [SECONDS.FRACTION] style: "[245.10302]"
    m = re.match(r'\s*\[(\d+\.\d+)\]', line)
    if m:
        ts_text = m.group(1)
        elapsed_ms = int(float(m.group(1)) * 1000)

    # "[component]" tags after the timestamp; the second tag is usually
    # the component name (e.g. [SSPWIFI], [NETWORKING]).
    tags = re.findall(r'\[([^\[\]]+)\]', line[:200])
    if len(tags) >= 3:
        component = tags[2]
    elif len(tags) >= 2:
        component = tags[1]
    return ts_text, elapsed_ms, component


def _make_finding(rule: Rule, lines: list[str], idx: int,
                  burst_indices: list[int] | None = None) -> Finding:
    line = lines[idx]
    ts_text, elapsed_ms, component = _extract_meta(line)
    before, after = _line_context(
        lines, idx, rule.context_lines_before, rule.context_lines_after,
    )
    burst_indices = burst_indices or []
    return Finding(
        rule_name=rule.name,
        category=rule.category,
        severity=rule.severity,
        description=rule.description,
        line_number=idx + 1,
        timestamp=ts_text,
        elapsed_ms=elapsed_ms,
        component=component,
        trigger_line=line,
        context_before=before,
        context_after=after,
        burst_line_numbers=[i + 1 for i in burst_indices],
        burst_size=max(1, len(burst_indices)),
    )


def _apply_single_rule(rule: Rule, lines: list[str],
                       line_elapsed: list[int],
                       ps_mask: list[bool] | None = None) -> list[Finding]:
    """Single-line rule: one finding per non-burst match."""
    out = []
    for idx, line in enumerate(lines):
        if ps_mask is not None and not ps_mask[idx]:
            continue
        if rule.matches(line):
            out.append(_make_finding(rule, lines, idx))
    return out


def _apply_burst_rule(rule: Rule, lines: list[str],
                      line_elapsed: list[int],
                      ps_mask: list[bool] | None = None) -> list[Finding]:
    """
    Burst rule: emit one finding per cluster of >= burst_min matches
    whose first and last hits are within burst_window_s seconds.
    """
    match_indices = [
        i for i, l in enumerate(lines)
        if (ps_mask is None or ps_mask[i]) and rule.matches(l)
    ]
    if len(match_indices) < rule.burst_min:
        return []

    window_ms = int(rule.burst_window_s * 1000)
    out = []
    i = 0
    while i < len(match_indices):
        start_idx = match_indices[i]
        start_ms = line_elapsed[start_idx]
        # Greedily extend the cluster.
        cluster = [start_idx]
        j = i + 1
        while j < len(match_indices):
            cand_idx = match_indices[j]
            cand_ms = line_elapsed[cand_idx]
            # If we don't have timestamps (both 0), fall back to line-gap.
            if start_ms == 0 and cand_ms == 0:
                if cand_idx - cluster[-1] > 50:
                    break
            elif cand_ms - start_ms > window_ms:
                break
            cluster.append(cand_idx)
            j += 1
        if len(cluster) >= rule.burst_min:
            out.append(_make_finding(rule, lines, cluster[0],
                                     burst_indices=cluster))
        i = j
    return out


def apply_rules(filepath: Path, rules: Iterable[Rule] | None = None
                ) -> list[Finding]:
    """Apply the rule library to the file and return raw Findings."""
    rules = list(rules) if rules is not None else get_rules()
    lines = _read_lines(filepath)
    # Only fire rules on lines that match the PS log format.
    # Non-PS debug lines are kept in the list for context windows but
    # are never themselves eligible to trigger a finding.
    ps_mask = [bool(_PS_LINE_RE.match(l)) for l in lines]
    # Pre-extract per-line elapsed_ms for burst-window computation.
    line_elapsed = [_extract_meta(l)[1] for l in lines]

    findings: list[Finding] = []
    for rule in rules:
        if rule.is_burst_rule:
            findings.extend(_apply_burst_rule(rule, lines, line_elapsed, ps_mask))
        else:
            findings.extend(_apply_single_rule(rule, lines, line_elapsed, ps_mask))
    return findings
