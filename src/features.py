import re
from src.parser import parse_file

_RSSI_VAL_RE = re.compile(r'RSSI:\s*(-?\d+)|Rssi\((-?\d+)\)')
_RSSI_LEVEL_MAP = {'EXCELLENT': 0, 'GOOD': 1, 'MARGINAL': 2, 'BAD': 3, 'POOR': 3}
_RSSI_LEVEL_RE = re.compile(r'rssiLevel\((\w+)\)|RSSI:\s*-?\d+\s+\((\w+)\)')
_LEVEL_NUM_RE = re.compile(r'Level(\d+)')

_EVENT_PATTERNS = {
    'flag_rssi_update':  'WIFI_STA_RSSI_UPDATE_IND_ID',
    'flag_bcn_snr_low':  'MLAN_EVENT_ID_FW_BCN_SNR_LOW',
    'flag_data_snr_low': 'MLAN_EVENT_ID_FW_DATA_SNR_LOW',
    'flag_defer_rx':     'MLAN_EVENT_ID_DRV_DEFER_RX_WORK',
    'flag_keepalive':    'REMOTE_NDIS_KEEPALIVE_MSG',
    'flag_deauth':       'Deauthent',
    'flag_assoc_fail':   'ASSOC_RESP',
    'flag_conn_fail':    'connection fail',
    'flag_ps_cmd':       'PS Command',
    'flag_wlan_irq':     'wlan_interrupt',
    'flag_wifi_stuck':   'WifiChannel: stuck',
    'flag_wifi_off':     'wifiOff',
}


def extract_line_features(entry: dict, prev_elapsed_ms) -> dict:
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

    level_str = entry.get('level', 'Unknown')
    m_lvl = _LEVEL_NUM_RE.match(level_str)
    if m_lvl:
        level_num = int(m_lvl.group(1))
    elif level_str == 'Error':
        level_num = 10
    elif level_str == 'Warning':
        level_num = 9
    else:
        level_num = 0

    component = entry.get('component', '').lower()
    flags = {k: int(pat.lower() in msg.lower()) for k, pat in _EVENT_PATTERNS.items()}

    delta_ms = elapsed - prev_elapsed_ms if prev_elapsed_ms is not None else 0

    return {
        'elapsed_ms':      elapsed,
        'delta_ms':        delta_ms,
        'rssi':            rssi_val if rssi_val is not None else 0,
        'has_rssi':        int(rssi_val is not None),
        'rssi_level':      rssi_level,
        'level_num':       level_num,
        'is_error':        int(entry.get('level') == 'Error'),
        'is_warning':      int(entry.get('level') == 'Warning'),
        'is_networking':   int('networking' in component),
        'is_sspwifi':      int('sspwifi' in component),
        **flags,
    }


def extract_features_from_file(filepath) -> list[dict]:
    """
    Parse a log file and return a list of per-line feature dicts.
    Each dict also carries 'elapsed_ms' for downstream segment timing.
    """
    features = []
    prev_ms = None
    for entry in parse_file(filepath):
        feat = extract_line_features(entry, prev_ms)
        prev_ms = entry['elapsed_ms']
        features.append(feat)
    return features


def extract_features_and_entries(filepath) -> tuple:
    """
    Parse a log file and return (feature_rows, entries) as parallel lists.
    feature_rows[i] and entries[i] correspond to the same log line.
    entries[i] contains the raw parsed log dict (timestamp, component, level, message).
    """
    features = []
    entries = []
    prev_ms = None
    for entry in parse_file(filepath):
        feat = extract_line_features(entry, prev_ms)
        prev_ms = entry['elapsed_ms']
        features.append(feat)
        entries.append(entry)
    return features, entries
