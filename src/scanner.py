"""
Top-level scan: produces a ranked list of developer-actionable Findings
for a single log file.

Pipeline:
  1. Rule engine applies the curated bug-signature library to raw lines.
  2. Rare-template detector flags log templates that never appeared in
     any normal-training file (filtered to error-bearing templates only).

The output is intentionally NOT window-based: developers want specific
incidents (line N: bug X), not aggregated window scores.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import asdict

from .parser import parse_file
from .drain import DrainTree, apply_drain
from .template_encoder import TemplateEncoder
from .rule_engine import apply_rules
from .rare_template_detector import detect as detect_rare, load as load_rare
from .findings import Finding, rank_findings


_CONFIG_PATH = Path(__file__).resolve().parent.parent / 'config.json'


def load_config() -> dict:
    """Load the project config.json."""
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def list_log_files(log_dir: Path) -> list[Path]:
    """Return all .log files in `log_dir`, excluding zone-identifier files."""
    files = sorted(Path(log_dir).glob('*.log'))
    return [f for f in files if not f.name.endswith('.Zone.Identifier')]


def load_model_artifacts(model_dir: Path) -> tuple[DrainTree | None,
                                                   TemplateEncoder | None]:
    """
    Load the Drain tree + semantic template encoder from `model_dir`.
    Returns (None, None) if the model has not been trained yet.
    """
    model_dir = Path(model_dir)
    drain_path   = model_dir / 'drain_tree.pkl'
    encoder_path = model_dir / 'template_encoder.pkl'
    if not drain_path.exists():
        return None, None
    drain_tree = DrainTree.load(drain_path)
    encoder = (TemplateEncoder.load(encoder_path)
               if encoder_path.exists() else None)
    return drain_tree, encoder


def parse_and_tag(fpath: Path, drain_tree: DrainTree,
                  encoder: TemplateEncoder | None) -> list[dict]:
    """
    Parse a log file and assign Drain template ids (event_id) to each entry.
    Used to power the rare-template detector.
    """
    entries = list(parse_file(fpath))
    if not entries:
        return []
    apply_drain(entries, drain_tree, frozen=True, encoder=encoder)
    return entries


def scan_file(filepath: Path,
              model_dir: Path | None = None,
              parsed_entries: list[dict] | None = None,
              max_rare: int = 15) -> list[Finding]:
    """
    Scan one log file and return ranked Findings.

    Args:
        filepath: path to the log file to analyze.
        model_dir: optional model directory for rare-template detection.
                   If None, rare-template detection is skipped.
        parsed_entries: optional pre-parsed entries (with event_id from
                        Drain). If supplied, rare-template detection runs.
        max_rare: maximum rare-template findings to emit (default 15).

    Returns:
        Findings sorted by actionability_score desc.
    """
    filepath = Path(filepath)

    # Layer 1: rule library (always runs).
    findings = apply_rules(filepath)

    # Layer 2: rare-template detection (if model is loaded and entries given).
    if model_dir is not None and parsed_entries is not None:
        normal_ids_path = Path(model_dir) / 'normal_template_ids.pkl'
        if normal_ids_path.exists():
            normal_ids = load_rare(normal_ids_path)
            if normal_ids:
                rare_findings = detect_rare(parsed_entries, normal_ids,
                                            max_findings=max_rare)
                # Avoid duplicating findings whose line is already flagged
                # by a higher-severity rule on the same line.
                rule_lines = {f.line_number for f in findings}
                for rf in rare_findings:
                    if rf.line_number not in rule_lines:
                        findings.append(rf)

    return rank_findings(findings)


def findings_to_json(findings: list[Finding]) -> list[dict]:
    """Serialize findings to a JSON-compatible list of dicts."""
    return [asdict(f) for f in findings]


def file_verdict(findings: list[Finding]) -> str:
    """
    Roll up findings to a single file-level verdict.

    A file is ANOMALOUS if any CRITICAL or HIGH finding fires.
    A file is SUSPICIOUS if only MEDIUM/LOW findings fire.
    Otherwise NORMAL.
    """
    if any(f.severity in ('CRITICAL', 'HIGH') for f in findings):
        return 'ANOMALOUS'
    if findings:
        return 'SUSPICIOUS'
    return 'NORMAL'


def write_report(filepath: Path, findings: list[Finding],
                 out_dir: Path) -> tuple[Path, Path] | None:
    """
    Write a JSON + Markdown report for one file. Returns (json_path,
    md_path) if findings exist, otherwise None (skip output for clean files).

    JSON goes to out_dir/json/, Markdown to out_dir/md/.
    """
    if not findings:
        return None

    out_dir = Path(out_dir)
    json_dir = out_dir / 'json'
    md_dir = out_dir / 'md'
    json_dir.mkdir(parents=True, exist_ok=True)
    md_dir.mkdir(parents=True, exist_ok=True)
    stem = filepath.stem

    json_path = json_dir / f'{stem}.findings.json'
    md_path   = md_dir / f'{stem}.findings.md'

    verdict = file_verdict(findings)
    payload = {
        'file': str(filepath),
        'verdict': verdict,
        'finding_count': len(findings),
        'findings': findings_to_json(findings),
    }
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(_render_markdown(filepath, verdict, findings))

    return json_path, md_path


def _render_markdown(filepath: Path, verdict: str,
                     findings: list[Finding]) -> str:
    lines = [
        f'# Anomaly Report: `{filepath.name}`',
        '',
        f'**Verdict:** `{verdict}`  |  **Findings:** {len(findings)}',
        '',
    ]
    if not findings:
        lines.append('_No developer-actionable anomalies detected._')
        return '\n'.join(lines) + '\n'

    # Severity summary.
    from collections import Counter
    sev_counts = Counter(f.severity for f in findings)
    summary = '  '.join(f'`{s}`: {sev_counts[s]}'
                        for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
                        if sev_counts.get(s))
    lines.append(f'**Severity summary:** {summary}')
    lines.append('')

    for i, f in enumerate(findings, 1):
        lines.append(f'## {i}. `{f.severity}` {f.description}')
        lines.append('')
        lines.append(f'- **Category:** {f.category}')
        lines.append(f'- **Line:** {f.line_number}  '
                     f'**Timestamp:** `{f.timestamp}`  '
                     f'**Component:** `{f.component}`  '
                     f'**Actionability:** {f.actionability_score:.2f}')
        if f.burst_size > 1:
            lines.append(f'- **Burst size:** {f.burst_size} matches '
                         f'starting at line {f.line_number}')
        lines.append('')
        lines.append('**Trigger line:**')
        lines.append('```')
        lines.append(f.trigger_line)
        lines.append('```')
        if f.context_before or f.context_after:
            lines.append('')
            lines.append('**Context:**')
            lines.append('```')
            for b in f.context_before:
                lines.append(f'  {b}')
            lines.append(f'> {f.trigger_line}')
            for a in f.context_after:
                lines.append(f'  {a}')
            lines.append('```')
        lines.append('')
        lines.append('---')
        lines.append('')

    return '\n'.join(lines) + '\n'
