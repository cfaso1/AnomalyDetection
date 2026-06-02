import json
import csv
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

from src.features import extract_features_from_file
from src.segmenter import segment_file

_CONFIG_PATH = Path(__file__).parent.parent / 'config.json'

_SEGMENT_FEATURE_COLS = [
    'duration_ms', 'line_count', 'lines_per_sec',
    'mean_rssi', 'min_rssi', 'mean_rssi_level',
    'error_rate', 'warning_rate',
    'flag_rssi_update_rate', 'flag_bcn_snr_low_rate', 'flag_data_snr_low_rate',
    'flag_defer_rx_rate', 'flag_keepalive_rate',
    'flag_deauth_rate', 'flag_assoc_fail_rate', 'flag_conn_fail_rate',
]


def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def load_artifacts(cfg: dict = None) -> tuple:
    """Load trained IF, scaler, and training score range from model_dir."""
    if cfg is None:
        cfg = _load_config()

    model_dir = Path(cfg['model_dir'])
    iso = joblib.load(model_dir / 'iso_forest.pkl')
    scaler = joblib.load(model_dir / 'scaler.pkl')
    if_score_range = joblib.load(model_dir / 'if_score_range.pkl')

    return iso, scaler, if_score_range


def score_segments(segments: list[dict], iso, scaler, if_score_range: dict, cfg: dict = None) -> list[dict]:
    """
    Score each segment with Isolation Forest using training-time score range for normalization.
    Returns segments with added score fields.
    """
    if cfg is None:
        cfg = _load_config()

    if not segments:
        return []

    df = pd.DataFrame(segments)
    X = df[_SEGMENT_FEATURE_COLS].values.astype(float)
    X_scaled = scaler.transform(X)

    if_raw = iso.decision_function(X_scaled)
    score_min = if_score_range['min']
    score_max = if_score_range['max']
    if_score = 1.0 - (if_raw - score_min) / (score_max - score_min + 1e-9)
    if_score = np.clip(if_score, 0.0, 1.0)

    threshold = cfg['anomaly_threshold']
    noise_floor = cfg['noise_cluster_floor']

    for i, seg in enumerate(segments):
        seg['anomaly_score'] = float(if_score[i])
        effective_score = max(if_score[i], noise_floor) if seg['is_noise'] else if_score[i]
        seg['is_anomalous'] = int(effective_score >= threshold)

    return segments


def score_file(fpath: Path, iso, scaler, if_score_range: dict, cfg: dict = None) -> list[dict]:
    """Full pipeline for a single file: parse -> segment -> score."""
    if cfg is None:
        cfg = _load_config()

    feats = extract_features_from_file(fpath)
    if not feats:
        return []

    segs = segment_file(feats, cfg)
    return score_segments(segs, iso, scaler, if_score_range, cfg)


def scan(log_dir: Path, cfg: dict = None) -> pd.DataFrame:
    """
    Score all log files in log_dir.
    Returns a DataFrame with one row per file summarising anomaly findings.
    """
    if cfg is None:
        cfg = _load_config()

    iso, scaler, if_score_range = load_artifacts(cfg)

    log_files = list(Path(log_dir).glob('*.log'))
    log_files = [f for f in log_files if not f.name.endswith('.Zone.Identifier')]

    rows = []
    for fpath in log_files:
        try:
            scored = score_file(fpath, iso, scaler, if_score_range, cfg)
            if not scored:
                continue

            n_segs = len(scored)
            n_anomalous = sum(s['is_anomalous'] for s in scored)
            max_score = max(s['anomaly_score'] for s in scored)
            mean_score = float(np.mean([s['anomaly_score'] for s in scored]))
            verdict = 'ANOMALOUS' if n_anomalous > 0 else 'normal'

            rows.append({
                'file': fpath.name,
                'n_segments': n_segs,
                'n_anomalous_segments': n_anomalous,
                'max_anomaly_score': round(max_score, 4),
                'mean_anomaly_score': round(mean_score, 4),
                'verdict': verdict,
            })

            print(f'  {fpath.name}: {verdict} '
                  f'({n_anomalous}/{n_segs} segments, max_score={max_score:.3f})')

        except Exception as e:
            print(f'  Warning: skipped {fpath.name}: {e}')

    return pd.DataFrame(rows)


def write_report(results: pd.DataFrame, cfg: dict = None):
    """Write scan results to outputs/report.csv."""
    if cfg is None:
        cfg = _load_config()

    output_dir = Path(cfg['output_dir'])
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / 'report.csv'
    results.to_csv(report_path, index=False)

    print(f'\nReport saved to {report_path}')
    print(f'  Total files scanned:  {len(results)}')
    print(f'  Anomalous files:      {(results["verdict"] == "ANOMALOUS").sum()}')
    print(f'  Normal files:         {(results["verdict"] == "normal").sum()}')
