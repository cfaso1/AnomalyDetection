#!/usr/bin/env python3
"""
Wi-Fi log bug-finder CLI.

Two subcommands:

    python run.py train <normal_dir> <anomaly_dir>
        Fit Drain parse tree + semantic encoder + record the set of
        normal-corpus template ids. Only needed once per dataset.

    python run.py find <log_dir> [--out-dir DIR]
        Scan every .log file in <log_dir> for developer-actionable
        bugs using the curated rule library and (if the model is
        trained) the rare-template detector. Writes one JSON +
        Markdown report per file under --out-dir
        (default: outputs/findings).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.trainer import train
from src.scanner import (
    scan_file, file_verdict, write_report,
    load_config, list_log_files, load_model_artifacts, parse_and_tag,
)


def _cmd_find(log_dir: Path, out_dir: Path):
    log_dir = Path(log_dir)
    out_dir = Path(out_dir)
    files = list_log_files(log_dir)
    if not files:
        print(f'No .log files in {log_dir}')
        return

    # Clear previous outputs
    json_dir = out_dir / 'json'
    md_dir = out_dir / 'md'
    if json_dir.exists():
        for f in json_dir.glob('*.findings.json'):
            f.unlink()
    if md_dir.exists():
        for f in md_dir.glob('*.findings.md'):
            f.unlink()
    # Clear summary from parent outputs/ directory
    summary_path = out_dir.parent / 'summary.json'
    if summary_path.exists():
        summary_path.unlink()

    cfg = load_config()
    model_dir = Path(cfg['model_dir'])
    drain_tree, encoder = load_model_artifacts(model_dir)
    if drain_tree is None:
        print('  Note: model not trained yet; running rule library only '
              '(rare-template detection disabled).')

    summary = []
    for fpath in files:
        parsed = (parse_and_tag(fpath, drain_tree, encoder)
                  if drain_tree is not None else None)
        findings = scan_file(
            fpath,
            model_dir=model_dir if drain_tree is not None else None,
            parsed_entries=parsed,
        )
        verdict = file_verdict(findings)
        sev = {s: sum(1 for f in findings if f.severity == s)
               for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
        summary.append({'file': fpath.name, 'verdict': verdict,
                        'findings': len(findings), 'severity': sev})
        print(f'  {fpath.name:<70s}  {verdict:<10s}  '
              f'{len(findings)} findings  '
              f'(C={sev["CRITICAL"]} H={sev["HIGH"]} '
              f'M={sev["MEDIUM"]} L={sev["LOW"]})')
        write_report(fpath, findings, out_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir.parent / 'summary.json'
    
    # Count verdicts
    verdict_counts = {'ANOMALOUS': 0, 'SUSPICIOUS': 0, 'NORMAL': 0}
    for item in summary:
        verdict_counts[item['verdict']] = verdict_counts.get(item['verdict'], 0) + 1
    
    summary_payload = {
        'total_files': len(summary),
        'verdict_counts': verdict_counts,
        'files': summary
    }
    
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary_payload, f, indent=2)
    
    print(f'\nSummary: {summary_path}')
    print(f'  Total files: {len(summary)}')
    print(f'  ANOMALOUS: {verdict_counts["ANOMALOUS"]}')
    print(f'  SUSPICIOUS: {verdict_counts["SUSPICIOUS"]}')
    print(f'  NORMAL: {verdict_counts["NORMAL"]}')
    print(f'Per-file reports: {out_dir}/<name>.findings.{{json,md}}')


def main():
    parser = argparse.ArgumentParser(
        description='Wi-Fi log bug-finder (rule-based + rare-template).'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p_train = sub.add_parser('train',
        help='Fit Drain parse tree, semantic encoder, normal-corpus template ids.')
    p_train.add_argument('normal_dir',  type=Path,
        help='Directory of normal log files (expected chaos).')
    p_train.add_argument('anomaly_dir', type=Path,
        help='Directory of buggy log files (used only to widen the Drain tree).')

    p_find = sub.add_parser('find',
        help='Scan a directory of logs for developer-actionable bugs.')
    p_find.add_argument('log_dir', type=Path,
        help='Directory of .log files to scan.')
    p_find.add_argument('--out-dir', type=Path,
        default=Path('outputs/findings'),
        help='Directory to write per-file reports (default: outputs/findings).')

    args = parser.parse_args()
    if args.command == 'train':
        print('=== Train ===\n')
        train(args.normal_dir, args.anomaly_dir)
    elif args.command == 'find':
        print('=== Find ===\n')
        _cmd_find(args.log_dir, args.out_dir)


if __name__ == '__main__':
    main()
