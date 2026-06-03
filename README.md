# Wi-Fi Log Anomaly Detection

Segment-based anomaly detection for Motorola Solutions Wi-Fi logs. Supports both unsupervised (Isolation Forest) and supervised (Random Forest classifier) detection modes.

## Overview

This pipeline parses PS-format Wi-Fi log files, segments them by behavioral patterns using DBSCAN clustering, and scores each segment for anomalous behaviour. When known-bad logs are available, a supervised Random Forest classifier is trained on labeled examples for significantly higher accuracy. An optional LLM integration produces plain-English explanations for each anomalous file.

## Log Format

Only the **PS log system** format is supported:

```
[198.11028] [wlanChan] [NETWORKING] WifiChannel: setAssociateRequestOption succeeded
[198.12776] [wlanChan] [SSPWIFI] nsi80211: setoption: type=28 len=3 seqnum=35
```

`[elapsed_seconds] [thread] [component] message`

DCMP date-time format logs are not processed and will be silently skipped.

## Project Structure

```
.
├── config.json              # Configuration parameters
├── run.py                   # CLI entry point
├── .env                     # API credentials (not committed)
├── .env.example             # Credential template
├── src/
│   ├── parser.py            # PS-format log parser
│   ├── features.py          # Per-line feature extraction
│   ├── segmenter.py         # DBSCAN clustering + segment aggregation
│   ├── trainer.py           # Isolation Forest + supervised classifier training
│   ├── detector.py          # Anomaly scoring, reporting, and excerpts
│   └── llm_reporter.py      # LLM-based anomaly explanation (optional)
├── logs/
│   ├── bad_logs/            # Known-anomalous PS-format logs (labeled training examples)
│   ├── good_logs/           # Confirmed-healthy PS-format logs (for training)
│   └── verification_logs/   # Held-out logs for testing model performance
├── training_logs/           # Healthy baseline logs (legacy location, still supported)
├── model/                   # Saved model artifacts (generated after training)
└── outputs/                 # Reports and excerpts (generated after scanning)
    ├── report.csv
    ├── llm_analysis.md
    └── excerpts/
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in credentials if using the LLM feature:

```bash
cp .env.example .env
```

## Workflow

### Option A — Unsupervised (no labeled bad logs)

Train on healthy logs only. The Isolation Forest learns the normal distribution and flags deviations from it.

```bash
python3 run.py train training_logs/
```

### Option B — Supervised (recommended when bad logs are available)

Provide both a normal directory and a known-bad directory. A Random Forest classifier is trained on labeled segment examples alongside the Isolation Forest. The classifier is used for scoring at scan time when present.

```bash
python3 run.py train logs/good_logs/ --anomaly-dir logs/bad_logs/
```

The supervised classifier directly learns the difference between normal and anomalous segment feature distributions, and is significantly more accurate than the unsupervised fallback when sufficient labeled examples exist.

Saved to `model/`:
- `iso_forest.pkl` — trained Isolation Forest (unsupervised fallback)
- `scaler.pkl` — RobustScaler fitted to normal training segments
- `if_score_range.pkl` — training-time decision function range
- `training_data.csv` — all normal training segments and features
- `classifier.pkl` — supervised Random Forest (only when `--anomaly-dir` is used)

### Scan for anomalies

```bash
python3 run.py scan logs/verification_logs/
```

Outputs:
- `outputs/report.csv` — per-file verdict and score summary
- `outputs/excerpts/` — top-N highest-scoring segments per anomalous file
- `outputs/llm_analysis.md` — plain-English explanations (if `llm_enabled: true`)

## Configuration (`config.json`)

| Parameter | Default | Description |
|---|---|---|
| `dbscan_eps` | `0.5` | DBSCAN neighbourhood radius |
| `dbscan_min_samples` | `5` | Minimum cluster size |
| `dbscan_downsample_threshold` | `10000` | Lines above this are downsampled before clustering |
| `if_n_estimators` | `100` | Number of trees in the Isolation Forest |
| `if_contamination` | `0.01` | Expected anomaly fraction in training data (unsupervised mode only) |
| `anomaly_threshold` | `0.8` | Score above which a segment is flagged. `0.5` is the natural classifier decision boundary; raise to reduce false positives |
| `anomaly_segment_fraction` | `0.3` | Minimum fraction of a file's segments that must exceed `anomaly_threshold` to flag the file as `ANOMALOUS`. Raise to suppress isolated single-segment hits |
| `max_excerpts_per_file` | `3` | Maximum number of excerpt files written per anomalous log file (top N by score) |
| `excerpt_max_notable_lines` | `200` | Max log lines written per excerpt file |
| `excerpt_window_size` | `50` | Sliding window size (lines) for peak sub-segment pinpointing |
| `llm_enabled` | `false` | Enable LLM anomaly explanation report |
| `llm_model` | `"VertexGemini"` | Model name passed to the in-house GenAI API |

## Pipeline Details

### 1. Parser (`src/parser.py`)
- PS-format only: `[elapsed_s] [thread] [component] message`
- Encoding fallback: UTF-8 → Latin-1 → CP1252
- Extracts: `elapsed_ms`, `line_num`, `component`, `level`, `message`
- Level parsed from message prefix: `Level5:`, `Level8:`, `Warning:`, `Error:`

### 2. Feature Extraction (`src/features.py`)

Extracts per-line features:

| Feature | Description |
|---|---|
| `elapsed_ms` | Absolute time in session (ms) |
| `delta_ms` | Time since previous line (ms); 0 for first line |
| `rssi`, `has_rssi`, `rssi_level` | Signal strength and quality |
| `level_num` | Numeric log severity (Level5=5 … Error=10) |
| `is_error`, `is_warning` | Error/Warning flags |
| `is_networking`, `is_sspwifi` | Component flags (NETWORKING vs SSPWIFI) |
| `flag_rssi_update` | WIFI_STA_RSSI_UPDATE_IND_ID event |
| `flag_bcn_snr_low` | Beacon SNR below threshold |
| `flag_data_snr_low` | Data SNR below threshold |
| `flag_defer_rx` | Deferred RX work event |
| `flag_deauth` | Deauthentication event |
| `flag_assoc_fail` | Association response failure |
| `flag_conn_fail` | Connection failure |
| `flag_ps_cmd` | Power save mode command |
| `flag_wlan_irq` | Hardware interrupt event |
| `flag_wifi_stuck` | WifiChannel stuck event |
| `flag_wifi_off` | WiFi disable event |

### 3. Segmentation (`src/segmenter.py`)
- DBSCAN clustering (`ball_tree` algorithm) groups lines by behavioral similarity
- Files >10K lines are dynamically downsampled before clustering
- Per-segment aggregated features:
  - Duration, line count, lines_per_sec
  - RSSI stats: mean, min, level
  - Error/warning rates (time-normalized)
  - All event flag rates (time-normalized)
  - `deauth_to_assoc_ratio` — state machine jitter indicator
  - `max_delta_t_ms` — longest silence gap (firmware freeze detection)
  - `max_rssi_drop` — largest RSSI swing within segment

### 4. Training (`src/trainer.py`)

**Unsupervised mode** (`train <normal_dir>`):
- Isolation Forest fitted on normal segment features
- `decision_function` range saved for score normalization at scan time

**Supervised mode** (`train <normal_dir> --anomaly-dir <bad_dir>`):
- Isolation Forest fitted on normal segments (unsupervised fallback)
- Random Forest binary classifier fitted on labeled segments (normal=0, anomaly=1)
- `class_weight='balanced'` handles the imbalance between few bad examples and many normal ones
- Cross-validated F1 score printed during training as a quality indicator

### 5. Detection (`src/detector.py`)
- If `classifier.pkl` exists in `model/`, classifier probability is used as the anomaly score (0–1)
- Otherwise, falls back to globally normalized Isolation Forest score
- A segment is flagged if its score exceeds `anomaly_threshold`
- A file is `ANOMALOUS` only if the fraction of flagged segments meets `anomaly_segment_fraction` — this suppresses files with a single spurious hit
- A sliding window scores sub-regions within each flagged segment to pinpoint the peak anomalous window
- Excerpt files written **only for `ANOMALOUS` files**, top `max_excerpts_per_file` segments by score, showing:
  - All features elevated above the 80th training percentile
  - All notable log lines in the peak window (errors, warnings, known events)
  - Full raw log lines when no notable events exist (behavioral/aggregate anomalies)

### 6. LLM Reporter (`src/llm_reporter.py`)
- Runs only when `llm_enabled: true` in `config.json`
- Reads excerpt files for each `ANOMALOUS` file
- Calls the in-house GenAI API (credentials from `.env`)
- Writes `outputs/llm_analysis.md` with a 2–4 sentence technical explanation per file

## LLM Setup

Set credentials in `.env`:

```
API_KEY=your_api_key_here
CORE_ID=your_core_id_here
```

Then enable in `config.json`:

```json
"llm_enabled": true,
"llm_model": "VertexGemini"
```

## Notes

- **Supervised vs unsupervised**: Use `--anomaly-dir` whenever you have confirmed bad examples — it directly learns the anomaly patterns rather than inferring them statistically.
- **Overfitting**: The supervised classifier will score 1.0 on its own training files. Always evaluate against held-out logs in `logs/verification_logs/`.
- **Two-level false positive control**: Use `anomaly_threshold` (per-segment score gate) and `anomaly_segment_fraction` (file-level fraction gate) together. A high score threshold plus a minimum segment fraction is effective at eliminating isolated noise hits while keeping true anomalies with many affected segments.
- **Retrain after any feature change**: Changes to `features.py`, `segmenter.py`, or `_SEGMENT_FEATURE_COLS` require a full retrain.
- **More bad examples = better generalisation**: Add more files to `logs/bad_logs/` and retrain to improve the classifier's ability to detect unseen anomaly types.
- **Excluded features**: `flag_keepalive_rate` is extracted but excluded from the model because zero-keepalive is normal in low-activity/power-save states and caused false positives. If future logs show keepalive absence as a genuine fault signal, re-add it to `_SEGMENT_FEATURE_COLS` in both `trainer.py` and `detector.py` and retrain.
- **Memory**: Large files are automatically downsampled before DBSCAN — controlled by `dbscan_downsample_threshold`.

## License

[Your License]
