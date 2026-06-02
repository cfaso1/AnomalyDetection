import json
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
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


def collect_segments(log_dir: Path, cfg: dict = None) -> list[dict]:
    """
    Parse and segment all log files in log_dir.
    Returns list of segment dicts.
    """
    if cfg is None:
        cfg = _load_config()

    log_files = list(Path(log_dir).glob('*.log'))
    log_files = [f for f in log_files if not f.name.endswith('.Zone.Identifier')]

    all_segments = []
    for fpath in log_files:
        try:
            feats = extract_features_from_file(fpath)
            if not feats:
                continue
            segs = segment_file(feats, cfg)
            all_segments.extend(segs)
        except Exception as e:
            print(f'  Warning: skipped {fpath.name}: {e}')

    return all_segments


def train_model(segments: list[dict], cfg: dict = None) -> tuple:
    """
    Train Isolation Forest (unsupervised) on all segments.
    Returns (iso_forest, scaler, training_df).
    """
    if cfg is None:
        cfg = _load_config()

    df = pd.DataFrame(segments)

    if len(df) == 0:
        raise ValueError('No segments found. Check log_dir contains valid log files.')

    print(f'  Total segments: {len(df)}')

    X = df[_SEGMENT_FEATURE_COLS].values.astype(float)

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=cfg['if_n_estimators'],
        contamination=cfg['if_contamination'],
        n_jobs=-1,
        random_state=42,
    )
    iso.fit(X_scaled)

    if_raw = iso.decision_function(X_scaled)
    if_score_range = {'min': float(if_raw.min()), 'max': float(if_raw.max())}

    print(f'  IF trained with contamination={cfg["if_contamination"]}')
    print(f'  IF decision function range: [{if_score_range["min"]:.4f}, {if_score_range["max"]:.4f}]')

    return iso, scaler, df, if_score_range


def save_artifacts(iso, scaler, training_df: pd.DataFrame, if_score_range: dict, cfg: dict = None):
    """Save model artifacts and training data to model_dir."""
    if cfg is None:
        cfg = _load_config()

    model_dir = Path(cfg['model_dir'])
    model_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(iso, model_dir / 'iso_forest.pkl')
    joblib.dump(scaler, model_dir / 'scaler.pkl')
    joblib.dump(if_score_range, model_dir / 'if_score_range.pkl')
    training_df.to_csv(model_dir / 'training_data.csv', index=False)

    print(f'  Saved: iso_forest.pkl, scaler.pkl, if_score_range.pkl, training_data.csv -> {model_dir}')


def train(log_dir: Path, cfg: dict = None):
    """Full training pipeline: parse -> segment -> train -> save."""
    if cfg is None:
        cfg = _load_config()

    print(f'Collecting segments from {log_dir}...')
    segments = collect_segments(log_dir, cfg)
    print(f'Total segments: {len(segments)}')

    print('\nTraining Isolation Forest...')
    iso, scaler, training_df, if_score_range = train_model(segments, cfg)

    print('\nSaving artifacts...')
    save_artifacts(iso, scaler, training_df, if_score_range, cfg)

    print('\nTraining complete.')
