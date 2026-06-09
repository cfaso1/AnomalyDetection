"""
Curated wifi / networking bug-signature library.

Each Rule encodes a *developer-actionable* anomaly: a log pattern whose
appearance reliably indicates a software bug (state-machine violation,
memory safety issue, firmware crash, protocol violation), as opposed to
environmental chaos like signal loss, DHCP failure, or DNS timeouts that
naturally occur when walking through elevators / stair-wells.

Each rule was validated against the labeled corpus
(logs/normal/*.log vs logs/anomaly/*.log):
- Patterns marked CLEAN have 0 occurrences in the normal corpus
  and >=1 in the anomaly corpus, so a single match is meaningful.
- Patterns marked BURST appear sporadically in normal logs but cluster
  densely (>= burst_min in <= burst_window_s seconds) only during bugs.
  These require burst detection, not single-line matching.

Severity levels:
- CRITICAL: memory-safety, firmware crash, protocol violations that
  *can only happen due to a software defect*. Always actionable.
- HIGH:     explicit error events from the system's own error-reporting
            channels. Almost always indicate a bug to investigate.
- MEDIUM:   suspicious patterns (failed operations with explicit error
            codes) that may or may not be bugs depending on context.
- LOW:      informational/contextual hits that aren't bugs by themselves
            but provide useful context for other findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# Severity levels in descending order of urgency.
SEVERITY_CRITICAL = 'CRITICAL'
SEVERITY_HIGH     = 'HIGH'
SEVERITY_MEDIUM   = 'MEDIUM'
SEVERITY_LOW      = 'LOW'

_SEVERITY_RANK = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH:     3,
    SEVERITY_MEDIUM:   2,
    SEVERITY_LOW:      1,
}


def severity_rank(level: str) -> int:
    return _SEVERITY_RANK.get(level, 0)


@dataclass
class Rule:
    """A single bug-signature detector."""

    name: str                             # internal id (snake_case)
    category: str                         # human-readable category
    severity: str                         # CRITICAL / HIGH / MEDIUM / LOW
    pattern: str                          # regex applied to raw line
    description: str                      # one-line headline shown to dev

    # Optional regex that disqualifies a match (e.g., a "voluntary
    # disconnect" line should not be flagged as a protocol bug).
    exclude_pattern: Optional[str] = None

    # If set, the rule only fires when >= `burst_min` matches occur within
    # `burst_window_s` seconds. Use for patterns that appear stray in
    # normal logs but cluster densely during bugs.
    burst_min: Optional[int] = None
    burst_window_s: Optional[float] = None

    # How many surrounding raw log lines to attach as context.
    context_lines_before: int = 5
    context_lines_after:  int = 5

    # Lazy-compiled.
    _re: Optional[re.Pattern] = field(default=None, init=False, repr=False)
    _ex: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def compile(self):
        self._re = re.compile(self.pattern, re.IGNORECASE)
        if self.exclude_pattern:
            self._ex = re.compile(self.exclude_pattern, re.IGNORECASE)

    def matches(self, line: str) -> bool:
        if self._re is None:
            self.compile()
        if not self._re.search(line):
            return False
        if self._ex is not None and self._ex.search(line):
            return False
        return True

    @property
    def is_burst_rule(self) -> bool:
        return self.burst_min is not None and self.burst_window_s is not None


# ---------------------------------------------------------------------------
# Curated rule library. Add new rules here as bug signatures are discovered.
# ---------------------------------------------------------------------------

BUG_RULES: list[Rule] = [
    # -------------------- CRITICAL: memory-safety bugs --------------------
    Rule(
        name='use_after_free_timer',
        category='Memory Safety',
        severity=SEVERITY_CRITICAL,
        pattern=r'check_for_bad_handle.*already free|already free.*timer|'
                r'use[- ]after[- ]free',
        description='Use-after-free on a kernel timer handle',
        context_lines_before=8,
        context_lines_after=8,
    ),

    # -------------------- CRITICAL: protocol violations -------------------
    Rule(
        name='deauth_reason_07_class3_frame',
        category='802.11 Protocol Violation',
        severity=SEVERITY_CRITICAL,
        pattern=r'Deauthenticated\s*\(reason\s*0x0?7\)',
        description='AP sent Deauth reason 0x07 (Class 3 frame from non-associated STA)',
        context_lines_before=10,
        context_lines_after=10,
    ),
    Rule(
        name='deauth_reason_0f_cipher_mismatch',
        category='802.11 Protocol Violation',
        severity=SEVERITY_CRITICAL,
        pattern=r'Deauthenticated\s*\(reason\s*0x0?f\)',
        description='AP sent Deauth reason 0x0F (group cipher / 4-way handshake failure)',
        context_lines_before=10,
        context_lines_after=10,
    ),
    Rule(
        name='deauth_unexpected_reason',
        category='802.11 Protocol Violation',
        severity=SEVERITY_HIGH,
        pattern=r'Deauthenticated\s*\(reason\s*0x[0-9a-f]+\)',
        # Don't double-fire on reasons that have their own dedicated rules.
        exclude_pattern=r'reason\s*0x0?[7f]\b',
        description='AP-initiated deauth with explicit reason code',
        context_lines_before=10,
        context_lines_after=10,
    ),

    # -------------------- CRITICAL: firmware-reported errors --------------
    Rule(
        name='firmware_diagnostic_error',
        category='Firmware Error Report',
        severity=SEVERITY_CRITICAL,
        pattern=r'Log Type:\s*DIAGNOSTIC\s*Error Msg:',
        # Some lines are continuation hex dumps; the burst rule below
        # handles the dump scenario. Here we want the single-line errors.
        description='Firmware emitted a DIAGNOSTIC-level Error report',
        context_lines_before=5,
        context_lines_after=15,  # often followed by hex dump
    ),
    Rule(
        name='firmware_error_burst',
        category='Firmware Error Report',
        severity=SEVERITY_CRITICAL,
        pattern=r'\|SSPLogger\s*\|Error:',
        description='Burst of SSPLogger error messages (likely firmware crash dump)',
        burst_min=5,
        burst_window_s=2.0,
        context_lines_before=3,
        context_lines_after=20,
    ),

    # -------------------- HIGH: protocol failures -------------------------
    Rule(
        name='association_rejected_with_status',
        category='802.11 Protocol Failure',
        severity=SEVERITY_HIGH,
        pattern=r'ASSOC_RESP[: ].*Association Failed.*status code\s*=\s*\d+',
        description='AP rejected association with an explicit status code',
        context_lines_before=8,
        context_lines_after=4,
    ),
    Rule(
        name='background_scan_failed',
        category='Driver Operation Failure',
        severity=SEVERITY_HIGH,
        pattern=r'WIFI_SET_BACKGROUND_SCAN_CNF with result failure',
        description='Background scan request returned a failure CNF',
    ),

    # -------------------- HIGH: TX/queue exhaustion (burst) ---------------
    Rule(
        name='tx_queue_overflow_storm',
        category='Resource Exhaustion',
        severity=SEVERITY_HIGH,
        pattern=r'SDPQueueManager.*classic queue full|'
                r'TreckNetworkAdapter send failure',
        description='Sustained TX queue overflow (driver back-pressure failure)',
        burst_min=10,
        burst_window_s=5.0,
        context_lines_before=4,
        context_lines_after=4,
    ),

    # -------------------- HIGH: watchdog / hard reset ---------------------
    Rule(
        name='watchdog_or_hard_reset',
        category='System Reset',
        severity=SEVERITY_HIGH,
        pattern=r'\bwatchdog\b.*\b(timeout|triggered|fired|reset)\b|'
                r'kernel panic|forced reboot',
        # RNDIS protocol defines a "hard reset" handshake that happens
        # routinely during USB host-device negotiation; it is NOT a fault.
        exclude_pattern=r'RNDIS|hardReset',
        description='Watchdog or kernel panic event observed',
        context_lines_before=15,
        context_lines_after=10,
    ),
]


def get_rules() -> list[Rule]:
    """Compile and return the curated rule list."""
    for r in BUG_RULES:
        r.compile()
    return BUG_RULES
