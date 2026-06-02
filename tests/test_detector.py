from src.detector import load_artifacts, score_file, scan, write_report, write_excerpts
from pathlib import Path

log_dir = Path('wifi_logs')

print('=== Step 1: Loading artifacts ===')
try:
    iso, scaler, if_score_range = load_artifacts()
    print(f'  IF loaded: {type(iso).__name__}')
    print(f'  Scaler loaded: {type(scaler).__name__}')
    print(f'  IF score range: [{if_score_range["min"]:.4f}, {if_score_range["max"]:.4f}]')
except Exception as e:
    print(f'  ERROR: {e}')
    exit(1)

print('\n=== Step 2: Scoring a single file ===')
test_file = next(log_dir.glob('*.log'))
try:
    scored, entries, feats = score_file(test_file, iso, scaler, if_score_range)
    print(f'  File: {test_file.name}')
    print(f'  Segments scored: {len(scored)}')
    print(f'  Entries (raw lines): {len(entries)}')
    print(f'  Anomalous segments: {sum(s["is_anomalous"] for s in scored)}')
    print(f'  Max anomaly score: {max(s["anomaly_score"] for s in scored):.4f}')

    print('\n  Sample scored segment:')
    sample = scored[0]
    for key in ['segment_id', 'is_noise', 'line_count', 'line_indices', 'anomaly_score', 'is_anomalous']:
        val = sample[key]
        if key == 'line_indices':
            val = f'[{val[0]}..{val[-1]}] ({len(val)} lines)'
        print(f'    {key}: {val}')
except Exception as e:
    print(f'  ERROR: {e}')
    exit(1)

print('\n=== Step 3: Scanning all files ===')
try:
    results, file_data = scan(log_dir)
    print(f'\n  Summary:')
    print(f'  Total files:     {len(results)}')
    print(f'  Anomalous files: {(results["verdict"] == "ANOMALOUS").sum()}')
    print(f'  Normal files:    {(results["verdict"] == "normal").sum()}')
except Exception as e:
    print(f'  ERROR: {e}')
    exit(1)

print('\n=== Step 4: Writing reports ===')
try:
    write_report(results)
    write_excerpts(file_data)
except Exception as e:
    print(f'  ERROR: {e}')
    exit(1)

print('\n=== All steps passed ===')
