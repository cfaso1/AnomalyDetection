# Wi-Fi Log Anomaly Detection

Segment-based anomaly detection for Wi-Fi logs using Isolation Forest.

## Overview

This pipeline processes Wi-Fi log files, segments them by behavioral patterns using DBSCAN clustering, and detects anomalies using an unsupervised Isolation Forest model. No ground truth labels are required.

## Project Structure

```
.
├── config.json          # Configuration file
├── run.py              # CLI entry point
├── src/
│   ├── parser.py       # Log parser with multi-format support
│   ├── features.py     # Per-line feature extraction
│   ├── segmenter.py    # DBSCAN clustering + segment aggregation
│   ├── trainer.py      # Isolation Forest training
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
- `if_n_estimators` — Number of trees in Isolation Forest (default: 100)
- `if_contamination` — Expected proportion of anomalies in the data (default: 0.05)
- `anomaly_threshold` — Score threshold to flag a segment as anomalous (default: 0.7)
- `noise_cluster_floor` — Minimum score applied to DBSCAN noise segments (default: 0.4)

## Usage

### Train Model

```bash
python3 run.py train wifi_logs
```

This will:
1. Parse all log files in `wifi_logs/`
2. Extract per-line features
3. Cluster lines into segments using DBSCAN
4. Train Isolation Forest on all segments
5. Save artifacts to `model/`:
   - `iso_forest.pkl`
   - `scaler.pkl`
   - `if_score_range.pkl`
   - `training_data.csv`

### Scan for Anomalies

```bash
python3 run.py scan wifi_logs
```

This will:
1. Load trained model from `model/`
2. Parse and segment each log file
3. Score each segment with the Isolation Forest
4. Write report to `outputs/report.csv`

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

### 4. Training (`src/trainer.py`)
- Isolation Forest trained on all segments (fully unsupervised)
- Records training-time decision function range for consistent scoring
- Saves model, scaler, and score range to disk

### 5. Detection (`src/detector.py`)
- Loads trained model and score range
- Scores each segment using training-time normalization for consistent cross-file comparison
- Noise segments get a minimum floor score
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

- **No labels needed**: Isolation Forest is fully unsupervised — no knowledge of which files are anomalous is required
- **Contamination**: Controls what fraction of data is expected to be anomalous; tune in `config.json` if results are too sensitive or not sensitive enough
- **Memory**: Large files (>10K lines) are automatically downsampled before DBSCAN clustering
- **Threshold**: Adjust `anomaly_threshold` in config to control sensitivity

## License

[Your License]
