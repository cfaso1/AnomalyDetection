import re
from src.parser import parse_file

_RSSI_VAL_RE = re.compile(r'RSSI:\s*(-?\d+)|Rssi\((-?\d+)\)')
_SEQ_NUM_RE = re.compile(r'seq_num=(\d+)')
_RSSI_LEVEL_MAP = {'EXCELLENT': 0, 'GOOD': 1, 'MARGINAL': 2, 'BAD': 3, 'POOR': 3}
_RSSI_LEVEL_RE = re.compile(r'rssiLevel\((\w+)\)|RSSI:\s*-?\d+\s+\((\w+)\)')

_EVENT_PATTERNS = {
    'flag_rssi_update':  'WIFI_STA_RSSI_UPDATE_IND_ID',
    'flag_bcn_snr_low':  'MLAN_EVENT_ID_FW_BCN_SNR_LOW',
    'flag_data_snr_low': 'MLAN_EVENT_ID_FW_DATA_SNR_LOW',
    'flag_defer_rx':     'MLAN_EVENT_ID_DRV_DEFER_RX_WORK',
    'flag_keepalive':    'REMOTE_NDIS_KEEPALIVE_MSG',
    'flag_deauth':       'Deauthent',
    'flag_assoc_fail':   'ASSOC_RESP',
    'flag_conn_fail':    'connection fail',
}


def extract_line_features(entry: dict, prev_elapsed_ms: int) -> dict:
    """
    Convert one parsed log entry into a numeric feature vector.
    Returns a flat dict of numeric values suitable for DBSCAN clustering.
    """
    msg = entry.get('message', '')
    elapsed = entry['elapsed_ms']

    rssi_val = None
    m = _RSSI_VAL_RE.search(msg)
    if m:
        raw = m.group(1) or m.group(2)
        rssi_val = int(raw) if raw else None

    rssi_level = -1
    m = _RSSI_LEVEL_RE.search(msg)
    if m:
        word = (m.group(1) or m.group(2) or '').upper()
        rssi_level = _RSSI_LEVEL_MAP.get(word, -1)

    seq_num = -1
    m = _SEQ_NUM_RE.search(msg)
    if m:
        seq_num = int(m.group(1))

    flags = {k: int(pat.lower() in msg.lower()) for k, pat in _EVENT_PATTERNS.items()}

    return {
        'elapsed_ms':      elapsed,
        'delta_ms':        elapsed - prev_elapsed_ms,
        'rssi':            rssi_val if rssi_val is not None else 0,
        'has_rssi':        int(rssi_val is not None),
        'rssi_level':      rssi_level,
        'seq_num':         seq_num,
        'is_error':        int(entry.get('level') == 'Error'),
        'is_warning':      int(entry.get('level') == 'Warning'),
        'is_ssplogger':    int('ssp' in entry.get('component', '').lower()),
        'log_format':      entry.get('format', 1),
        **flags,
    }


def extract_features_from_file(filepath) -> list[dict]:
    """
    Parse a log file and return a list of per-line feature dicts.
    Each dict also carries 'elapsed_ms' for downstream segment timing.
    """
    features = []
    prev_ms = 0
    for entry in parse_file(filepath):
        feat = extract_line_features(entry, prev_ms)
        prev_ms = entry['elapsed_ms']
        features.append(feat)
    return features
