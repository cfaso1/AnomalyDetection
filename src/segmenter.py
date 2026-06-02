import json
import numpy as np
from pathlib import Path
from sklearn.preprocessing import RobustScaler
from sklearn.cluster import DBSCAN

_CONFIG_PATH = Path(__file__).parent.parent / 'config.json'

_FEATURE_COLS = [
    'elapsed_ms', 'delta_ms', 'rssi', 'has_rssi', 'rssi_level',
    'seq_num', 'is_error', 'is_warning', 'is_ssplogger', 'log_format',
    'flag_rssi_update', 'flag_bcn_snr_low', 'flag_data_snr_low',
    'flag_defer_rx', 'flag_keepalive', 'flag_deauth', 'flag_assoc_fail',
    'flag_conn_fail',
]

_FLAG_COLS = [
    'flag_rssi_update', 'flag_bcn_snr_low', 'flag_data_snr_low',
    'flag_defer_rx', 'flag_keepalive', 'flag_deauth',
    'flag_assoc_fail', 'flag_conn_fail',
]


def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def cluster_lines(feature_rows: list[dict], cfg: dict = None) -> np.ndarray:
    """
    Run DBSCAN on per-line feature rows.
    For large files, downsamples before clustering then expands labels back.
    Returns an array of cluster labels (int). Label -1 means noise.
    """
    if cfg is None:
        cfg = _load_config()

    n = len(feature_rows)
    threshold = cfg.get('dbscan_downsample_threshold', 10000)
    factor = max(1, n // threshold)

    sampled_indices = list(range(0, n, factor))
    sampled_rows = [feature_rows[i] for i in sampled_indices]

    X = np.array([[row[c] for c in _FEATURE_COLS] for row in sampled_rows], dtype=float)
    X = RobustScaler().fit_transform(X)

    sampled_labels = DBSCAN(
        eps=cfg['dbscan_eps'],
        min_samples=cfg['dbscan_min_samples'],
        algorithm='ball_tree',
        metric='euclidean',
        n_jobs=-1,
    ).fit_predict(X)

    if factor == 1:
        return sampled_labels

    full_labels = np.full(n, -1, dtype=int)
    for i, (si, label) in enumerate(zip(sampled_indices, sampled_labels)):
        end = sampled_indices[i + 1] if i + 1 < len(sampled_indices) else n
        full_labels[si:end] = label

    return full_labels


def build_segments(feature_rows: list[dict], labels: np.ndarray, cfg: dict = None) -> list[dict]:
    """
    Aggregate per-line features into per-segment feature vectors.
    Noise lines (label -1) are collected into a single noise segment.
    Returns a list of segment dicts ready for RF/IF scoring.
    """
    if cfg is None:
        cfg = _load_config()

    clusters: dict[int, list[int]] = {}
    for i, label in enumerate(labels):
        clusters.setdefault(int(label), []).append(i)

    segments = []
    for label, indices in clusters.items():
        rows = [feature_rows[i] for i in indices]
        elapsed_vals = [r['elapsed_ms'] for r in rows]
        start_ms = min(elapsed_vals)
        end_ms = max(elapsed_vals)
        duration_ms = max(end_ms - start_ms, 1)
        duration_s = duration_ms / 1000.0
        n = len(rows)

        seg = {
            'segment_id':       label,
            'is_noise':         int(label == -1),
            'line_indices':     sorted(indices),
            'start_elapsed_ms': start_ms,
            'end_elapsed_ms':   end_ms,
            'duration_ms':      duration_ms,
            'line_count':       n,
            'lines_per_sec':    n / duration_s,
            'mean_rssi':        float(np.mean([r['rssi'] for r in rows])),
            'min_rssi':         float(np.min([r['rssi'] for r in rows])),
            'mean_rssi_level':  float(np.mean([r['rssi_level'] for r in rows])),
            'error_rate':       sum(r['is_error'] for r in rows) / duration_s,
            'warning_rate':     sum(r['is_warning'] for r in rows) / duration_s,
        }

        for flag in _FLAG_COLS:
            seg[flag + '_rate'] = sum(r[flag] for r in rows) / duration_s

        deauth_count = sum(r['flag_deauth'] for r in rows)
        assoc_count = sum(r['flag_assoc_fail'] for r in rows)
        seg['deauth_to_assoc_ratio'] = deauth_count / max(assoc_count, 1)
        seg['max_delta_t_ms'] = float(max((r['delta_ms'] for r in rows), default=0))

        segments.append(seg)

    return segments


def segment_file(feature_rows: list[dict], cfg: dict = None) -> list[dict]:
    """
    Full pipeline: cluster lines then aggregate into segment feature vectors.
    Returns list of segment dicts.
    """
    if not feature_rows:
        return []
    if cfg is None:
        cfg = _load_config()
    labels = cluster_lines(feature_rows, cfg)
    return build_segments(feature_rows, labels, cfg)
