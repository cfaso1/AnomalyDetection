# Wi-Fi Log Anomaly Detection

Segment-based anomaly detection for Motorola Solutions Wi-Fi logs using Isolation Forest.

## Overview

This pipeline parses PS-format Wi-Fi log files, segments them by behavioral patterns using DBSCAN clustering, and detects anomalies using an unsupervised Isolation Forest model. No ground truth labels are required for detection.

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
├── config.json          # Configuration parameters
├── run.py               # CLI entry point
├── src/
│   ├── parser.py        # PS-format log parser
│   ├── features.py      # Per-line feature extraction
│   ├── segmenter.py     # DBSCAN clustering + segment aggregation
│   ├── trainer.py       # Isolation Forest training
│   └── detector.py      # Anomaly scoring, reporting, and excerpts
├── training_logs/       # Healthy baseline PS-format logs (for training)
├── bad_logs/            # Known-bad PS-format logs (for scanning/validation)
├── model/               # Saved model artifacts (generated after training)
└── outputs/             # Reports and excerpts (generated after scanning)
    ├── report.csv
    └── excerpts/
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Workflow

### 1. Train on healthy baseline logs

Place clean, healthy PS-format logs in `training_logs/`, then run:

```bash
python3 run.py train training_logs/
```

Saves to `model/`:
- `iso_forest.pkl` — trained Isolation Forest
- `scaler.pkl` — RobustScaler fitted to training segments
- `if_score_range.pkl` — training-time score range for global normalization
- `training_data.csv` — all training segments and features

### 2. Scan for anomalies

```bash
python3 run.py scan bad_logs/
```

Outputs:
- `outputs/report.csv` — per-file verdict and score summary
- `outputs/excerpts/` — notable log lines for each anomalous segment

## Configuration (`config.json`)

| Parameter | Default | Description |
|---|---|---|
| `dbscan_eps` | 0.5 | DBSCAN neighbourhood radius |
| `dbscan_min_samples` | 5 | Minimum cluster size |
| `dbscan_downsample_threshold` | 10000 | Lines above this are downsampled before clustering |
| `if_n_estimators` | 100 | Number of trees in the Isolation Forest |
| `if_contamination` | 0.05 | Expected anomaly fraction in training data |
| `anomaly_threshold` | 0.6 | Score above which a segment is flagged (0–1) |
| `anomaly_segment_fraction` | 0.0 | Minimum fraction of segments that must be anomalous to flag a file (0.0 = any single anomalous segment flags the file) |
| `noise_cluster_floor` | 0.4 | Minimum effective score applied to DBSCAN noise segments |
| `excerpt_max_notable_lines` | 100 | Max notable lines written per excerpt file |

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
| `flag_keepalive` | Keepalive message |
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
- Isolation Forest trained fully unsupervised on all segments
- Training-time `decision_function` range saved for global normalization
- Scores during scan are normalized against training min/max — not per-batch

### 5. Detection (`src/detector.py`)
- Segments scored using globally normalized anomaly score (0–1)
- Noise (DBSCAN label -1) segments receive a minimum floor score
- A file is ANOMALOUS if at least one non-noise segment exceeds `anomaly_threshold`
- Excerpt files written for each anomalous segment showing:
  - Elevated features vs training data percentiles
  - Notable log lines (errors, warnings, known PS-format events)

## Testing

```bash
python3 -m tests.test_parser
python3 -m tests.test_features
python3 -m tests.test_segmenter
python3 -m tests.test_trainer
python3 -m tests.test_detector
```

## Notes

- **Training data quality matters**: The model learns "normal" from `training_logs/`. If bad logs are included in training, the model's sensitivity degrades. Use only confirmed healthy PS-format logs for training.
- **Retrain after any feature change**: Changes to `features.py`, `segmenter.py`, or `_SEGMENT_FEATURE_COLS` require a full retrain.
- **Threshold tuning**: Lower `anomaly_threshold` to increase sensitivity. The default 0.6 is conservative.
- **Memory**: Large files are automatically downsampled before DBSCAN — controlled by `dbscan_downsample_threshold`.

## License

[Your License]
