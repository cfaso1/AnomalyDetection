from src.features import extract_features_from_file
from pathlib import Path

log_dir = Path('wifi_logs')
log_files = list(log_dir.glob('*.log'))
log_files = [f for f in log_files if not f.name.endswith('.Zone.Identifier')]

EXPECTED_FIELDS = [
    'elapsed_ms', 'delta_ms', 'rssi', 'has_rssi', 'rssi_level',
    'seq_num', 'is_error', 'is_warning', 'is_ssplogger', 'log_format',
    'flag_rssi_update', 'flag_bcn_snr_low', 'flag_data_snr_low',
    'flag_defer_rx', 'flag_keepalive', 'flag_deauth', 'flag_assoc_fail',
    'flag_conn_fail',
]

print(f'Found {len(log_files)} log files\n')

errors = []
rssi_files = []
for fpath in log_files:
    try:
        feats = extract_features_from_file(fpath)
        if not feats:
            continue

        missing = [f for f in EXPECTED_FIELDS if f not in feats[0]]
        if missing:
            errors.append((fpath.name, f'Missing fields: {missing}'))
            continue

        has_rssi = [f for f in feats if f['has_rssi'] == 1]
        has_error = [f for f in feats if f['is_error'] == 1]
        has_warning = [f for f in feats if f['is_warning'] == 1]

        print(f'  {fpath.name}: {len(feats)} lines | '
              f'rssi={len(has_rssi)} | error={len(has_error)} | warning={len(has_warning)}')

        if has_rssi:
            rssi_files.append((fpath.name, has_rssi[0]))
    except Exception as e:
        errors.append((fpath.name, str(e)))

if rssi_files:
    print(f'\n=== First RSSI sample (from {rssi_files[0][0]}) ===')
    for k, v in rssi_files[0][1].items():
        print(f'  {k}: {v}')

if errors:
    print(f'\n=== Errors: {len(errors)} ===')
    for name, err in errors:
        print(f'  {name}: {err}')
else:
    print('\n=== No errors ===')
