from src.trainer import collect_segments, train_model, save_artifacts
from pathlib import Path

log_dir = Path('wifi_logs')

print('=== Step 1: Collecting segments ===')
segments = collect_segments(log_dir)
print(f'Total segments: {len(segments)}')

if len(segments) == 0:
    print('\nERROR: No segments found. Check log_dir.')
    exit(1)

print('\n=== Step 2: Training Isolation Forest ===')
try:
    iso, scaler, training_df, if_score_range = train_model(segments)
    print(f'  IF n_estimators: {iso.n_estimators}')
    print(f'  IF contamination: {iso.contamination}')
    print(f'  IF score range: [{if_score_range["min"]:.4f}, {if_score_range["max"]:.4f}]')
except Exception as e:
    print(f'\nERROR during training: {e}')
    exit(1)

print('\n=== Step 3: Saving artifacts ===')
try:
    save_artifacts(iso, scaler, training_df, if_score_range)
except Exception as e:
    print(f'\nERROR saving artifacts: {e}')
    exit(1)

print('\n=== All steps passed ===')
