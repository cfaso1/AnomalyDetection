import json
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import cross_val_score
import joblib

from src.features import extract_features_from_file
from src.segmenter import segment_file

_CONFIG_PATH = Path(__file__).parent.parent / 'config.json'

_SEGMENT_FEATURE_COLS = [
    'duration_ms', 'line_count', 'lines_per_sec',
    'mean_rssi', 'min_rssi', 'mean_rssi_level',
    'error_rate', 'warning_rate',
    'flag_rssi_update_rate', 'flag_bcn_snr_low_rate', 'flag_data_snr_low_rate',
    'flag_defer_rx_rate',
    'flag_deauth_rate', 'flag_assoc_fail_rate', 'flag_conn_fail_rate',
    'flag_ps_cmd_rate', 'flag_wlan_irq_rate', 'flag_wifi_stuck_rate', 'flag_wifi_off_rate',
    'deauth_to_assoc_ratio', 'max_delta_t_ms', 'max_rssi_drop',
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


def save_artifacts(iso, scaler, training_df: pd.DataFrame, if_score_range: dict,
                   cfg: dict = None, classifier=None):
    """Save model artifacts and training data to model_dir."""
    if cfg is None:
        cfg = _load_config()

    model_dir = Path(cfg['model_dir'])
    model_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(iso, model_dir / 'iso_forest.pkl')
    joblib.dump(scaler, model_dir / 'scaler.pkl')
    joblib.dump(if_score_range, model_dir / 'if_score_range.pkl')
    training_df.to_csv(model_dir / 'training_data.csv', index=False)

    saved = 'iso_forest.pkl, scaler.pkl, if_score_range.pkl, training_data.csv'
    if classifier is not None:
        joblib.dump(classifier, model_dir / 'classifier.pkl')
        saved += ', classifier.pkl'

    print(f'  Saved: {saved} -> {model_dir}')


def collect_labeled_segments(normal_dir: Path, anomaly_dir: Path, cfg: dict = None) -> tuple:
    """
    Collect segments from both normal and anomaly directories with labels.
    Returns (segments, labels) where label=0 is normal, label=1 is anomalous.
    """
    if cfg is None:
        cfg = _load_config()

    normal_segments = collect_segments(normal_dir, cfg)
    anomaly_segments = collect_segments(anomaly_dir, cfg)

    print(f'  Normal segments:   {len(normal_segments)} (from {normal_dir})')
    print(f'  Anomalous segments:{len(anomaly_segments)} (from {anomaly_dir})')

    segments = normal_segments + anomaly_segments
    labels = [0] * len(normal_segments) + [1] * len(anomaly_segments)
    return segments, labels


def train_classifier(segments: list[dict], labels: list[int], scaler, cfg: dict = None):
    """
    Train a Random Forest binary classifier on labeled segments.
    Returns (classifier, cv_score).
    """
    if cfg is None:
        cfg = _load_config()

    df = pd.DataFrame(segments)
    X = df[_SEGMENT_FEATURE_COLS].values.astype(float)
    X_scaled = scaler.transform(X)
    y = np.array(labels)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_scaled, y)

    cv_scores = cross_val_score(clf, X_scaled, y, cv=min(5, sum(y)), scoring='f1')
    print(f'  Classifier F1 (cross-val): {cv_scores.mean():.3f} ± {cv_scores.std():.3f}')

    return clf


def train(log_dir: Path, cfg: dict = None, anomaly_dir: Path = None):
    """Full training pipeline: parse -> segment -> train -> save."""
    if cfg is None:
        cfg = _load_config()

    if anomaly_dir is not None:
        print(f'Collecting labeled segments...')
        segments, labels = collect_labeled_segments(log_dir, anomaly_dir, cfg)
        print(f'Total segments: {len(segments)}')

        print('\nTraining Isolation Forest on normal segments...')
        normal_segs = [s for s, l in zip(segments, labels) if l == 0]
        iso, scaler, training_df, if_score_range = train_model(normal_segs, cfg)

        print('\nTraining supervised Random Forest classifier...')
        clf = train_classifier(segments, labels, scaler, cfg)

        print('\nSaving artifacts...')
        save_artifacts(iso, scaler, training_df, if_score_range, cfg, classifier=clf)
    else:
        print(f'Collecting segments from {log_dir}...')
        segments = collect_segments(log_dir, cfg)
        print(f'Total segments: {len(segments)}')

        print('\nTraining Isolation Forest...')
        iso, scaler, training_df, if_score_range = train_model(segments, cfg)

        print('\nSaving artifacts...')
        save_artifacts(iso, scaler, training_df, if_score_range, cfg)

    print('\nTraining complete.')
