from src.features import extract_features_from_file
from src.segmenter import segment_file
from pathlib import Path

log_dir = Path('wifi_logs')
log_files = list(log_dir.glob('*.log'))
log_files = [f for f in log_files if not f.name.endswith('.Zone.Identifier')]

print(f'Found {len(log_files)} log files\n')

errors = []
for fpath in log_files:
    try:
        feats = extract_features_from_file(fpath)
        if not feats:
            continue

        segs = segment_file(feats)
        noise_segs = [s for s in segs if s['is_noise'] == 1]
        n_segs = len(segs)
        n_noise = len(noise_segs)
        noise_lines = noise_segs[0]['line_count'] if noise_segs else 0
        noise_pct = round(100 * noise_lines / len(feats), 1) if feats else 0

        print(f'  {fpath.name}: {len(feats)} lines -> '
              f'{n_segs} segments ({n_segs - n_noise} clusters + {n_noise} noise) | '
              f'noise lines: {noise_lines} ({noise_pct}%)')
    except Exception as e:
        errors.append((fpath.name, str(e)))

if errors:
    print(f'\n=== Errors: {len(errors)} ===')
    for name, err in errors:
        print(f'  {name}: {err}')
else:
    print('\n=== No errors ===')

print('\n=== Sample segment fields ===')
try:
    feats = extract_features_from_file('wifi_logs/8987_hidden_sc_08272024.log')
    segs = segment_file(feats)
    for k, v in segs[0].items():
        print(f'  {k}: {v}')
except Exception as e:
    print(f'  ERROR: {e}')
