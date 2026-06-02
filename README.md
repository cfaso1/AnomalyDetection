# Wi-Fi Log Anomaly Detection

Segment-based anomaly detection for Wi-Fi logs using Random Forest and Isolation Forest.

## Overview

This pipeline processes Wi-Fi log files, segments them by behavioral patterns using DBSCAN clustering, and detects anomalies using a hybrid Random Forest (supervised) + Isolation Forest (unsupervised) approach.

## Project Structure

```
.
├── config.json          # Configuration file
├── run.py              # CLI entry point
├── src/
│   ├── parser.py       # Log parser with multi-format support
│   ├── features.py     # Per-line feature extraction
│   ├── segmenter.py    # DBSCAN clustering + segment aggregation
│   ├── labeler.py      # Filename-based labeling
│   ├── trainer.py      # Model training (RF + IF)
│   └── detector.py     # Anomaly detection and reporting
├── wifi_logs/          # Directory for log files
├── model/              # Saved model artifacts (after training)
└── outputs/            # Scan reports (after scanning)
```

## Installation

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Edit `config.json` to adjust parameters:

- `dbscan_eps`, `dbscan_min_samples` — DBSCAN clustering parameters
- `dbscan_downsample_threshold` — Memory threshold for downsampling (default: 10000)
- `rf_n_estimators`, `rf_max_depth`, `rf_min_samples_leaf` — Random Forest hyperparameters
- `if_n_estimators`, `if_contamination` — Isolation Forest hyperparameters
- `rf_weight`, `if_weight` — Score combination weights (default: 0.6/0.4)
- `anomaly_threshold` — Threshold for anomaly flag (default: 0.5)
- `noise_cluster_floor` — Minimum score for noise segments (default: 0.4)
- `anomalous_filename_keywords` — Keywords for anomalous files
- `normal_filename_keywords` — Keywords for normal files

## Usage

### Train Models

```bash
python3 run.py train wifi_logs
```

This will:
1. Parse all log files in `wifi_logs/`
2. Extract per-line features
3. Cluster lines into segments using DBSCAN
4. Label segments based on filename keywords
5. Train Random Forest (supervised) and Isolation Forest (unsupervised)
6. Save artifacts to `model/`:
   - `rf_classifier.pkl`
   - `iso_forest.pkl`
   - `scaler.pkl`
   - `training_data.csv`

### Scan for Anomalies

```bash
python3 run.py scan wifi_logs
```

This will:
1. Load trained models from `model/`
2. Parse and segment each log file
3. Score each segment with RF + IF
4. Combine scores using configured weights
5. Write report to `outputs/report.csv`

## Pipeline Details

### 1. Parser (`src/parser.py`)
- Supports two Motorola Wi-Fi log formats
- Encoding fallback: UTF-8 → Latin-1 → CP1252
- Streaming parser for memory efficiency
- Extracts: timestamp, elapsed time, component, level, message

### 2. Feature Extraction (`src/features.py`)
- Extracts 17 numeric features per line:
  - Timing: elapsed_ms, delta_ms
  - RSSI: rssi, has_rssi, rssi_level
  - Sequence: seq_num
  - Flags: is_error, is_warning, is_ssplogger, log_format
  - Event flags: rssi_update, bcn_snr_low, data_snr_low, defer_rx, keepalive, deauth, assoc_fail, conn_fail

### 3. Segmentation (`src/segmenter.py`)
- DBSCAN clustering with ball_tree algorithm
- Dynamic downsampling for large files (>10K lines)
- Aggregates per-segment statistics:
  - Duration, line count, lines_per_sec
  - RSSI stats: mean, min, level
  - Error/warning rates
  - Event flag rates (time-normalized)

### 4. Labeling (`src/labeler.py`)
- Labels segments based on filename keywords
- Labels: 1 (anomalous), 0 (normal), -1 (unknown)
- All segments from same file get same label

### 5. Training (`src/trainer.py`)
- Random Forest: Supervised on labeled segments
- Isolation Forest: Unsupervised on normal segments only
- 80/20 train/test split with stratification
- Saves models and training data

### 6. Detection (`src/detector.py`)
- Loads trained models
- Scores each segment: RF probability + IF score
- Combined score: `rf_weight * rf_score + if_weight * if_score`
- Noise segments get minimum floor score
- File flagged as ANOMALOUS if any segment exceeds threshold

## Testing

Run test scripts to verify each module:

```bash
python3 -m tests.test_parser      # Test parser on all files
python3 -m tests.test_features    # Test feature extraction
python3 -m tests.test_segmenter   # Test DBSCAN clustering
python3 -m tests.test_trainer     # Test model training
python3 -m tests.test_detector    # Test anomaly detection
```

## Notes

- Memory: Large files (>10K lines) are automatically downsampled before DBSCAN clustering
- Labels: Based on filename keywords — ensure your naming convention reflects ground truth
- Threshold: Adjust `anomaly_threshold` in config if too many/false positives
- Noise: Noise clusters (label -1) get a floor score but are not necessarily anomalous

## License

[Your License]
