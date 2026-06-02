import json
import csv
import shutil
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

from src.features import extract_features_and_entries
from src.segmenter import segment_file

_CONFIG_PATH = Path(__file__).parent.parent / 'config.json'

_NOTABLE_LEVELS = {'Error', 'Warning'}
_NOTABLE_PATTERNS = [
    'WIFI_STA_RSSI_UPDATE_IND_ID', 'MLAN_EVENT_ID_FW_BCN_SNR_LOW',
    'MLAN_EVENT_ID_FW_DATA_SNR_LOW', 'MLAN_EVENT_ID_DRV_DEFER_RX_WORK',
    'REMOTE_NDIS_KEEPALIVE_MSG', 'Deauthent', 'ASSOC_RESP', 'connection fail',
]

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


def _format_elapsed(elapsed_ms: int) -> str:
    """Format elapsed milliseconds as HH:MM:SS.mmm."""
    ms = elapsed_ms % 1000
    s = (elapsed_ms // 1000) % 60
    m = (elapsed_ms // 60000) % 60
    h = elapsed_ms // 3600000
    return f'{h:02d}:{m:02d}:{s:02d}.{ms:03d}'


def score_file(fpath: Path, iso, scaler, if_score_range: dict, cfg: dict = None) -> tuple:
    """Full pipeline for a single file: parse -> segment -> score.
    Returns (scored_segments, raw_entries, feature_rows) as parallel structures.
    """
    if cfg is None:
        cfg = _load_config()

    feats, entries = extract_features_and_entries(fpath)
    if not feats:
        return [], [], []

    segs = segment_file(feats, cfg)
    scored = score_segments(segs, iso, scaler, if_score_range, cfg)
    return scored, entries, feats


def scan(log_dir: Path, cfg: dict = None) -> tuple:
    """
    Score all log files in log_dir.
    Returns (summary_df, file_data) where file_data is a list of dicts
    with keys: fpath, segments (scored), entries (raw log entries).
    """
    if cfg is None:
        cfg = _load_config()

    iso, scaler, if_score_range = load_artifacts(cfg)

    log_files = list(Path(log_dir).glob('*.log'))
    log_files = [f for f in log_files if not f.name.endswith('.Zone.Identifier')]

    rows = []
    file_data = []
    for fpath in log_files:
        try:
            scored, entries, feats = score_file(fpath, iso, scaler, if_score_range, cfg)
            if not scored:
                continue

            n_segs = len(scored)
            n_anomalous = sum(s['is_anomalous'] for s in scored)
            n_anomalous_real = sum(s['is_anomalous'] for s in scored if not s['is_noise'])
            max_score = max(s['anomaly_score'] for s in scored)
            mean_score = float(np.mean([s['anomaly_score'] for s in scored]))
            min_fraction = cfg.get('anomaly_segment_fraction', 0.0)
            verdict = 'ANOMALOUS' if n_anomalous_real > 0 and (n_anomalous / n_segs) >= min_fraction else 'normal'

            rows.append({
                'file': fpath.name,
                'n_segments': n_segs,
                'n_anomalous_segments': n_anomalous,
                'max_anomaly_score': round(max_score, 4),
                'mean_anomaly_score': round(mean_score, 4),
                'verdict': verdict,
            })
            file_data.append({'fpath': fpath, 'segments': scored, 'entries': entries, 'feats': feats})

            print(f'  {fpath.name}: {verdict} '
                  f'({n_anomalous}/{n_segs} segments, max_score={max_score:.3f})')

        except Exception as e:
            print(f'  Warning: skipped {fpath.name}: {e}')

    return pd.DataFrame(rows), file_data


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


def _is_notable(entry: dict) -> bool:
    """Return True if a log entry is notable (error, warning, or known event)."""
    if entry.get('level') in _NOTABLE_LEVELS:
        return True
    msg = entry.get('message', '').lower()
    return any(pat.lower() in msg for pat in _NOTABLE_PATTERNS)


def write_excerpts(file_data: list, cfg: dict = None):
    """
    Write outputs/excerpts/<filename>_seg<id>.txt for every anomalous segment.
    Only notable lines (errors, warnings, known events) are included.
    """
    if cfg is None:
        cfg = _load_config()

    excerpts_dir = Path(cfg['output_dir']) / 'excerpts'

    # Clear old per-file subdirectories
    if excerpts_dir.exists():
        for item in excerpts_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
    excerpts_dir.mkdir(parents=True, exist_ok=True)

    training_path = Path(cfg['model_dir']) / 'training_data.csv'
    training_df = pd.read_csv(training_path) if training_path.exists() else None
    max_lines = cfg.get('excerpt_max_notable_lines', 100)

    total = 0
    for fd in file_data:
        fname = fd['fpath'].name
        entries = fd['entries']
        n_anomalous = sum(s['is_anomalous'] for s in fd['segments'])

        for seg in fd['segments']:
            if not seg['is_anomalous']:
                continue

            seg_id = seg['segment_id']
            line_indices = seg.get('line_indices', [])
            seg_entries = [entries[i] for i in sorted(line_indices) if i < len(entries)]

            first_ln = seg_entries[0]['line_num'] if seg_entries else '?'
            last_ln = seg_entries[-1]['line_num'] if seg_entries else '?'

            notable = [e for e in seg_entries if _is_notable(e)]
            truncated = len(notable) > max_lines
            notable = notable[:max_lines]

            elevated_summary = ''
            if training_df is not None:
                elevated = []
                for col in _SEGMENT_FEATURE_COLS:
                    val = float(seg.get(col, 0.0))
                    train_vals = training_df[col].values
                    pct = float(np.mean(train_vals <= val)) * 100
                    nonzero_frac = float(np.mean(train_vals > 0))
                    if pct >= 80 and (val > 0 or nonzero_frac > 0.05):
                        elevated.append((col, val, pct))
                elevated.sort(key=lambda x: -x[2])
                if elevated:
                    elevated_summary = '\n'.join(
                        f'  {c}: {v:.4f}  (top {100 - p:.0f}% of training)'
                        for c, v, p in elevated[:5]
                    )

            if n_anomalous > 1:
                file_dir = excerpts_dir / fname
                file_dir.mkdir(exist_ok=True)
                out_path = file_dir / f'seg{seg_id}.txt'
            else:
                safe_name = fname.replace(' ', '_').replace('(', '').replace(')', '')
                out_path = excerpts_dir / f'{safe_name}_seg{seg_id}.txt'

            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(f'=== Anomalous Segment ===\n')
                f.write(f'File:         {fname}\n')
                f.write(f'Segment ID:   {seg_id}\n')
                f.write(f'Anomaly score:{seg["anomaly_score"]:.4f}\n')
                f.write(f'Noise segment:{"yes" if seg["is_noise"] else "no"}\n')
                f.write(f'Line range:   {first_ln} - {last_ln} ({seg["line_count"]} lines)\n')
                f.write(f'Time range:   {_format_elapsed(seg["start_elapsed_ms"])}'
                        f' - {_format_elapsed(seg["end_elapsed_ms"])}\n')
                f.write(f'Duration:     {seg["duration_ms"]} ms\n')

                if elevated_summary:
                    f.write(f'\n--- Elevated Features (vs training data) ---\n')
                    f.write(elevated_summary + '\n')

                f.write(f'\n--- Notable Lines (errors / warnings / events) ---\n\n')

                if not notable:
                    f.write('  [no notable lines — segment flagged for aggregate behavior]\n')
                else:
                    for e in notable:
                        ts = _format_elapsed(e['elapsed_ms'])
                        comp = e.get('component', '')
                        level = e.get('level', '')
                        msg = e.get('message', '')
                        f.write(f'[{ts}] [{comp}] [{level}] {msg}\n')
                    if truncated:
                        f.write(f'\n[... truncated at {max_lines} notable lines ...]\n')

            total += 1

    print(f'  Excerpts written: {total} files -> {excerpts_dir}/')
