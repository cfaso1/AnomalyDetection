# Wi-Fi Log Anomaly Detection — Batch File Scanner

A CLI tool that scans a directory of Wi-Fi `.log` files, uses DBSCAN to cluster log lines into behavioral segments per file, scores each segment with a trained RF + Isolation Forest model, and outputs a ranked list of files with pinpointed anomalous time windows.

---

## Design: 3-Tier Hybrid Detection

The core insight is that Wi-Fi logs have natural behavioral phases (scanning, connecting, data transfer, degradation). DBSCAN discovers these phases without needing to pre-define window sizes. Each phase becomes a scored unit.

```
wifi logs/ (directory of .log files)
        │
        ▼  for each file:
   parser.py  ──►  features.py         segmenter.py
   (parse lines)    (per-line features) (DBSCAN → segments)
                          │                    │
                          └────────┬───────────┘
                                   ▼
                         Segment Feature Matrix
                         (one row per segment)
                                   │
                            ┌──────┴──────┐
                            ▼             ▼
                           RF            ISO
                       Classifier       Forest
                       (supervised)  (unsupervised)
                            └──────┬──────┘
                                   ▼
                         Anomalous segments flagged
                                   │
                                   ▼
                         File rollup: flagged if
                         ≥ 1 anomalous segment
                                   │
                                   ▼
                      anomaly_report.md / .csv
                      (ranked files + segment timestamps)
```

### Why DBSCAN for Segmentation
- **No preset window size needed** — segments are defined by where behavior actually changes
- **Noise points (label = -1)** are isolated lines that don't fit any cluster — themselves strong anomaly candidates
- **Handles variable density** — normal connected-state traffic is dense; anomalous events are sparse
- **Natural phases emerge**: scanning clusters, keepalive clusters, data-transfer clusters, degradation clusters

---

## Feature Extraction (Two Levels)

### Level 1 — Per-Line Features (input to DBSCAN)
Extracted from each parsed log line for clustering:

| Feature | Description |
|---|---|
| `rssi_val` | Numeric RSSI (dBm), or 0 if absent |
| `rssi_cat` | EXCELLENT=0, GOOD=1, MARGINAL=2, missing=-1 |
| `log_level` | Level5=5, Level6=6, Level8=8, Warning=9 |
| `component` | SSPLogger=0, Networking=1, other=2 |
| `delta_t_ms` | Elapsed time delta from previous line |
| `seq_delta` | Packet sequence number delta (0 if absent) |
| `flag_bcn_snr_low` | Binary: `MLAN_EVENT_ID_FW_BCN_SNR_LOW` present |
| `flag_data_snr_low` | Binary: `MLAN_EVENT_ID_FW_DATA_SNR_LOW` present |
| `flag_defer_rx` | Binary: `MLAN_EVENT_ID_DRV_DEFER_RX_WORK` present |
| `flag_conn_fail` | Binary: `TELNET.*FAIL` present |
| `rx_len` | RX packet length (0 if absent) |

### Level 2 — Per-Segment Features (input to RF + IF)
Each DBSCAN cluster → one aggregated feature row. All event counts **time-normalized** (per minute of segment duration) to eliminate duration bias:

| Feature | Description |
|---|---|
| `mean_rssi` | Average RSSI within segment |
| `min_rssi` | Worst RSSI in segment |
| `rssi_std` | RSSI variability within segment |
| `rssi_marginal_fraction` | Fraction of RSSI readings labeled MARGINAL |
| `bcn_snr_low_rate` | `MLAN_EVENT_ID_FW_BCN_SNR_LOW` events **per minute** |
| `data_snr_low_rate` | `MLAN_EVENT_ID_FW_DATA_SNR_LOW` events **per minute** |
| `defer_rx_rate` | `MLAN_EVENT_ID_DRV_DEFER_RX_WORK` events **per minute** |
| `conn_fail_rate` | Connection failure events **per minute** |
| `seq_gap_rate` | Packet sequence gaps **per minute** |
| `warning_fraction` | Fraction of lines at Warning level |
| `mean_delta_t_ms` | Average timing gap within segment |
| `max_delta_t_ms` | Largest timing gap within segment |
| `segment_duration_min` | Segment duration in minutes |
| `is_noise_cluster` | 1 if this segment is DBSCAN noise (label = -1) |

> **Duration bias note:** All rate features divide by `segment_duration_min`. A noise cluster (single isolated line) gets `is_noise_cluster=1` and its rates are computed over its local time window.

---

## AI Models

### DBSCAN — Behavioral Segmentation (per file)
- Runs on the per-line feature matrix for each file
- Parameters: `eps=0.5` (tunable), `min_samples=5`, metric=Euclidean on `RobustScaler`-normalized features
- Output: cluster label per line; label `-1` = noise (isolated anomalous line)
- Lines are grouped into segments; noise lines form their own single-line segments with `is_noise_cluster=1`

### Supervised — Random Forest Classifier (per segment)
- Input: labeled per-segment feature matrix
- **Anomalous segment sources**: segments from `beaconLost`/`NoisyEnv` files that contain known bad events
- **Normal segment sources**: segments from clean `SC` runs
- Output: anomaly probability per segment (0.0–1.0)
- Parameters: `n_estimators=200`, `max_depth=4`, `min_samples_leaf=2`, `class_weight='balanced'`, `random_state=42`
- `max_depth=4` + `min_samples_leaf=2` force generalized structural patterns, not memorized file profiles

### Unsupervised — Isolation Forest (per segment)
- Trained on normal-only segment rows
- Catches segment types not represented in labeled data
- Output: anomaly score per segment

### Score Combination
- IF raw scores normalized to `[0, 1]` via: `IF_norm = (score − min) / (max − min)`
- Segment final score = `0.6 × RF_probability + 0.4 × IF_norm`
- Segment flagged if score ≥ 0.5; DBSCAN noise segments (`is_noise_cluster=1`) get a score floor of 0.4

### File Rollup
- File is flagged if **any** segment score ≥ 0.5
- File score = max segment score within the file
- Key signals in report = top features of the highest-scoring segment

---

## Technology Stack

| Layer | Library |
|---|---|
| Language | Python 3.10+ |
| Data | `pandas`, `numpy` |
| Parsing | `re`, `chardet` (encoding fallback) |
| Segmentation | `scikit-learn` `DBSCAN` — behavioral clustering of log lines |
| ML | `scikit-learn` `RandomForestClassifier`, `IsolationForest` |
| Scaling | `RobustScaler` (median + IQR — resistant to RSSI/timing outliers) |
| Model persistence | `joblib` |
| I/O | `pathlib`, `csv`, `json` |

No GPU required.

---

## Project Structure

```
attempt3AnomalyDetection/
├── requirements.txt
├── README.md
├── PLAN.md
├── config.json              # Thresholds, model params, keyword lists
├── run.py                   # CLI entry point
├── src/
│   ├── __init__.py
│   ├── parser.py            # Stream-parse .log lines, encoding fallback, skip headers
│   ├── features.py          # Per-line feature extraction (Level 1 — input to DBSCAN)
│   ├── segmenter.py         # DBSCAN clustering → per-segment feature aggregation (Level 2)
│   ├── labeler.py           # Label segments from known-bad/good files for training
│   ├── trainer.py           # Train RF + IF on labeled segment rows, save to model/
│   └── detector.py          # Load model, score all files in a dir, write report
├── model/
│   ├── rf_classifier.pkl
│   ├── iso_forest.pkl
│   ├── scaler.pkl
│   └── training_data.csv    # Labeled segment rows (saved for reproducibility)
└── outputs/
    ├── anomaly_report.md
    └── anomaly_report.csv
```

---

## Output Format

### `anomaly_report.md`
```
# Wi-Fi Log Anomaly Report
Generated: 2026-06-01 10:30:00
Directory: wifi logs/
Files scanned: 50 | Files flagged: 12

## Flagged Files (ranked by file score)

| Rank | File | Score | Anomalous Segments | Top Signals |
|---|---|---|---|---|
| 1 | 243_beaconLost_27dbm_APX8000SC_8987_ITR1.log | 0.94 | 3 of 8 | bcn_snr_low_rate=4.5/min, min_rssi=-78 |
| 2 | 243_LQ_Mahalo_NoisyEnv_09032024.log | 0.87 | 2 of 6 | data_snr_low_rate=2.1/min, rssi_marginal_fraction=0.31 |

### 243_beaconLost_27dbm_APX8000SC_8987_ITR1.log — Segment Detail
| Segment | Time Window | Score | Key Signals |
|---|---|---|---|
| Cluster 3 | 00:04:00 – 00:05:28 | 0.94 | bcn_snr_low_rate=4.5/min, min_rssi=-78 |
| Noise | 00:12:03 – 00:12:03 | 0.72 | is_noise_cluster, flag_defer_rx |
| Cluster 7 | 00:18:45 – 00:19:30 | 0.61 | seq_gap_rate=0.8/min |

## Clean Files (score < 0.5)
243_8777.log (0.12), 243_mahalo.log (0.18), ...
```

### `anomaly_report.csv`
Two output tables:
- **File-level**: `file, file_score, flagged, total_segments, anomalous_segments, top_signal`
- **Segment-level**: `file, segment_id, cluster_label, time_start, time_end, score, rf_probability, if_score, is_noise_cluster, mean_rssi, min_rssi, bcn_snr_low_rate, ...`

---

## CLI Usage

```bash
pip install -r requirements.txt

# One-time: train the model on the labeled log directory
python run.py --train --logs-dir "wifi logs/"

# Scan a directory and get the ranked report
python run.py --scan "wifi logs/"

# Scan a different directory with a custom threshold
python run.py --scan "new_logs/" --threshold 0.4
```

---

## 3-Month Timeline

### Month 1 — Parser + Per-Line Features + Segmentation (Weeks 1–4)
- `parser.py`: stream-parse log format, encoding fallback (UTF-8 → latin-1 → cp1252), skip Motorola headers
- `features.py`: extract per-line feature vector (Level 1); apply `RobustScaler`; fill missing values with 0
- `segmenter.py`: run DBSCAN on per-line features; aggregate clusters into per-segment feature rows (Level 2) with time-normalized rates; tag noise clusters
- Tune DBSCAN `eps` on a sample of log files to produce meaningful behavioral segments

### Month 2 — Model Training (Weeks 5–8)
- `labeler.py`: label segments from known-bad files (`beaconLost`, `NoisyEnv`, `Bad/`) as anomalous; label segments from clean files as normal; produce `training_data.csv`
- `trainer.py`: train RF + IF on labeled segment rows, evaluate on 20% holdout (target: precision ≥ 0.75, recall ≥ 0.70), save models

### Month 3 — Integration + Validation (Weeks 9–12)
- `detector.py`: load models; for each file → parse → per-line features → DBSCAN segments → score segments → roll up to file score; write ranked MD + CSV report
- `run.py`: wire up `--train` and `--scan` CLI modes
- Test on all 50+ existing logs; tune `eps`, RF threshold, and IF contamination; write README

---

## Success Criteria

- **Coverage**: All `beaconLost` and `NoisyEnv` files appear in the flagged list
- **Precision**: ≥ 75% of flagged files are genuinely problematic (validated by engineer)
- **Speed**: Full directory of 50 files scanned in < 5 minutes
- **Usability**: `pip install` + two commands to train and scan
