# Wi-Fi Log Bug Finder — Rule-Based + Rare-Template Detection

Developer-focused bug diagnostics for Motorola Solutions Wi-Fi infrastructure logs. Identifies software and hardware system bugs — race conditions, state-machine failures, driver crashes, and unhandled exceptions — using a curated rule library combined with rare-template detection.

## System Architecture

The redesigned system abandons the previous dual-engine ML approach in favor of a deterministic, rule-based pipeline that ignores normal environmental chaos (e.g., elevator/stairwell low signal) and surfaces only developer-actionable bugs.

```
                      ┌─────────────────────────┐
  Raw .log file ──▶   │  Phase 1: Ingestion      │
                      │  Parser + Drain          │
                      └────────────┬────────────┘
                                   │  Parsed entries
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
         ┌─────────────────┐           ┌─────────────────┐
         │   Rule Engine    │           │  Rare-Template  │
         │  (Regex + Burst)│           │   Detector      │
         │                  │           │                  │
         │ Curated patterns │           │ Never-seen-in-   │
         │ for known bugs   │           │ normal templates │
         └────────┬─────────┘           └────────┬─────────┘
                  └──────────────┬───────────────┘
                                 ▼
                      ┌─────────────────────┐
                      │  Findings Ranker    │
                      │  Actionability      │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │  JSON + Markdown    │
                      │  Report Output      │
                      └─────────────────────┘
```

### Layer 1: Rule Engine

A curated library of regex patterns and burst detectors for known Wi-Fi bug signatures:

- **Single-line rules**: Match specific error patterns (e.g., `failed`, `crash`, `exception`)
- **Burst rules**: Detect repeated occurrences within a time window (e.g., watchdog resets, deauth storms)
- **Severity levels**: CRITICAL, HIGH, MEDIUM, LOW
- **Actionability scoring**: Each finding is ranked by how actionable it is for a developer

### Layer 2: Rare-Template Detector

Flags log templates that never appeared in the normal training corpus, filtered to error-bearing messages only. This catches novel failure modes that weren't covered by the rule library.

### Output: Ranked Findings

Each finding includes:
- Exact line number and raw trigger line
- Context lines (before/after)
- Severity and category
- Why it matters (developer explanation)
- Common root causes
- Actionability score

## Log Format

PS log system format only. Non-PS debug lines are silently ignored during scanning.

```
[198.11028] [wlanChan] [NETWORKING] WifiChannel: setAssociateRequestOption succeeded
[198.12776] [wlanChan] [SSPWIFI] nsi80211: setoption: type=28 len=3 seqnum=35
```

`[elapsed_seconds] [thread] [component] message`

## Project Structure

```
.
├── config.json              # Drain and semantic encoder parameters
├── run.py                   # CLI entry point (train + find)
├── gui.py                   # DAWG — single-file analysis GUI
├── src/
│   ├── parser.py            # PS-format log parser
│   ├── drain.py             # Drain log template extraction (event_id assignment)
│   ├── template_encoder.py  # Semantic template encoder (hash fallback)
│   ├── rules.py             # Curated wifi bug-signature library
│   ├── rule_engine.py       # Apply rules to raw lines (PS-format only)
│   ├── rare_template_detector.py  # Flag novel error-bearing templates
│   ├── findings.py          # Finding dataclass + actionability ranking
│   ├── scanner.py           # Top-level scan_file + report writer
│   └── trainer.py           # Fit Drain + encoder + normal template set
├── logs/
│   ├── normal/              # Confirmed-healthy logs (environmental chaos OK)
│   ├── anomaly/             # Known-buggy logs (to widen Drain tree only)
│   └── unlabeled/           # Logs to analyze after training
├── model/                   # Saved artifacts (generated after training)
│   ├── drain_tree.pkl
│   ├── template_encoder.pkl
│   └── normal_template_ids.pkl
└── outputs/                 # Reports (generated after scanning)
    ├── summary.json         # Per-file verdict summary
    └── findings/
        ├── json/            # Machine-readable findings per file
        └── md/              # Human-readable findings per file
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Workflow

### 1. Prepare training data

Place confirmed-healthy log files in `logs/normal/` and confirmed-buggy log files in `logs/anomaly/`. The system requires **both** directories to train.

```
logs/
  normal/    ← PS-format logs with no known bugs (may contain environmental chaos)
  anomaly/   ← PS-format logs containing confirmed bugs (used only to widen Drain tree)
```

### 2. Train

```bash
python3 run.py train logs/normal/ logs/anomaly/
```

Training steps:
1. Fit the **Drain parse tree** on all log files — discovers log templates, assigns stable `event_id`s
2. Fit the **semantic template encoder** — enables OOV template resolution via nearest-neighbor lookup
3. Record the **normal-corpus event_id set** — used by the rare-template detector to flag novel templates

Artifacts saved to `model/`:

| File | Contents |
|---|---|
| `drain_tree.pkl` | Fitted Drain parse tree (event vocabulary) |
| `template_encoder.pkl` | Semantic encoder (hash fallback for offline use) |
| `normal_template_ids.pkl` | Set of event_ids seen in normal logs |

### 3. Scan

```bash
python3 run.py find logs/unlabeled/ --out-dir outputs/findings
```

For each log file:
- Parse → Drain → rule engine → rare-template detector (if model trained)
- Findings are ranked by actionability score
- JSON + Markdown reports are written per file (clean files produce no output)

Outputs:

| File | Contents |
|---|---|
| `outputs/summary.json` | Per-file verdict summary (ANOMALOUS, SUSPICIOUS, NORMAL) |
| `outputs/findings/json/<name>.findings.json` | Machine-readable findings (only for anomalous files) |
| `outputs/findings/md/<name>.findings.md` | Human-readable findings (only for anomalous files) |

### 4. GUI (single-file analysis)

```bash
python3 gui.py
```

Browse to a `.log` file and click **Analyze**. The GUI renders findings inline with severity badges, context lines, and developer explanations. Requires trained models in `model/` for rare-template detection; otherwise, only the rule library runs.

## Finding Output Format

Each anomalous file produces a structured findings report:

```json
{
  "file": "/path/to/logfile.log",
  "verdict": "ANOMALOUS",
  "finding_count": 3,
  "findings": [
    {
      "rule_name": "watchdog_reset",
      "category": "Driver Crash",
      "severity": "CRITICAL",
      "description": "System watchdog reset detected",
      "line_number": 1234,
      "timestamp": "198.11028",
      "elapsed_ms": 198110,
      "component": "NETWORKING",
      "trigger_line": "[198.11028] [wlanChan] [NETWORKING] Watchdog reset: reason=0x1",
      "context_before": ["[198.10000] ...", "[198.10500] ..."],
      "context_after": ["[198.11500] ...", "[198.12000] ..."],
      "burst_line_numbers": [1234, 1245, 1256],
      "burst_size": 3,
      "actionability_score": 0.95
    }
  ]
}
```

## Configuration (`config.json`)

### Drain

| Parameter | Default | Description |
|---|---|---|
| `drain_sim_threshold` | `0.5` | Minimum token-match ratio to merge a message into an existing template |
| `drain_max_children` | `128` | Max templates per (length, prefix) bucket before wildcard fallback |

### Semantic Encoder

| Parameter | Default | Description |
|---|---|---|
| `semantic_model` | `"hash"` | `"hash"` for offline use, or HuggingFace model id for semantic embeddings |
| `semantic_dim` | `384` | Embedding dimension (used only if semantic_model is not "hash") |
| `semantic_proj_dim` | `32` | Projection dimension for downstream use |
| `oov_min_similarity` | `0.55` | Minimum cosine similarity for OOV template resolution |

## Notes

- **Retrain after config changes**: Changing `drain_sim_threshold` or `semantic_model` requires a full retrain.
- **Normal logs may contain chaos**: The rule library is designed to ignore normal environmental failures (e.g., low signal in elevators, routine deauths).
- **Rare-template detector requires training**: If the model is not trained, only the rule library runs.
- **Non-PS lines are ignored**: Debug lines that don't match the PS format are silently skipped during scanning.
- **Clean files produce no output**: Files with no findings are not written to disk (only summary.json includes them).

## License

[Your License]
