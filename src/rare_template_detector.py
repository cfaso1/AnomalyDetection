"""
Rare-template detector.

During training we record the set of (Drain) templates that appear in the
NORMAL corpus. At scan time, any template encountered in the target log
that was never seen in any normal-training file is a candidate finding.

This catches developer-actionable anomalies that the curated rule library
might miss (new error messages introduced by a feature, novel firmware
strings, etc.) without re-flagging environmental chaos: by definition,
DHCP failures, DNS timeouts, association drops, etc. are already in the
normal corpus and therefore won't fire.

Caveats handled:
  - Drain templates whose IDs differ purely due to thread-name truncation
    (`wlanCha` vs `wlanChan`) and similar lexical artifacts are *not*
    automatically merged here; we rely on the semantic template encoder's
    nearest-neighbor lookup at parse time to resolve those.
  - Templates that only appear in a single normal file with a single
    occurrence are still considered "in the normal corpus" - rarity in
    the normal set is not a bug signal.
"""
from __future__ import annotations

import pickle
from pathlib import Path

from .findings import Finding
from .rules import SEVERITY_MEDIUM


def build_normal_template_set(normal_event_ids: set[str]) -> set[str]:
    """The set of event_ids the model considers 'normal'."""
    return set(normal_event_ids)


def save(path: Path, normal_event_ids: set[str]):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f:
        pickle.dump({'normal_event_ids': set(normal_event_ids)}, f)


def load(path: Path) -> set[str]:
    path = Path(path)
    if not path.exists():
        return set()
    with open(path, 'rb') as f:
        return set(pickle.load(f).get('normal_event_ids', set()))


import re

# Only flag rare templates that look like error/failure reports. Routine
# state-machine transitions, config events, and informational messages that
# happen to be missing from the normal corpus are usually corpus-alignment
# artifacts (different log levels, capture durations, thread name truncation)
# rather than real bugs.
_ERROR_HINT_RE = re.compile(
    r'\b(error|fail|failure|failed|exception|abort|panic|fatal|stuck|hang|'
    r'corrupt|invalid|denied|reject|overflow|underflow|leak|timeout)\b',
    re.IGNORECASE,
)


def detect(entries: list[dict],
           normal_event_ids: set[str],
           max_findings: int = 20) -> list[Finding]:
    """
    Walk through parsed entries and emit Findings for the first
    occurrence of each rare event_id (event_id that never appeared in the
    normal-training corpus). Filtered to error-bearing templates only.
    """
    seen: set[str] = set()
    out: list[Finding] = []
    for e in entries:
        eid = e.get('event_id', '')
        if not eid or eid == '<unk>':
            continue
        if eid in normal_event_ids:
            continue
        if eid in seen:
            continue
        # Suppress non-error-looking rare templates.
        text = (e.get('template', '') or '') + ' ' + (e.get('message', '') or '')
        if not _ERROR_HINT_RE.search(text):
            continue
        seen.add(eid)
        out.append(Finding(
            rule_name='rare_template',
            category='Novel Log Template',
            severity=SEVERITY_MEDIUM,
            description=(
                f'Log template not present in any normal-training file: '
                f'"{e.get("template", "")[:120]}"'
            ),
            line_number=e.get('line_num', 0),
            timestamp=f"{e.get('elapsed_ms', 0) / 1000.0:.3f}",
            elapsed_ms=e.get('elapsed_ms', 0),
            component=e.get('component', ''),
            trigger_line=e.get('message', ''),
            rare_template=True,
        ))
        if len(out) >= max_findings:
            break
    return out
