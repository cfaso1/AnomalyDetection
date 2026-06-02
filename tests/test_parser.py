from src.parser import parse_file, _detect_encoding
from pathlib import Path

log_dir = Path('wifi_logs')
log_files = list(log_dir.glob('*.log'))
log_files = [f for f in log_files if not f.name.endswith('.Zone.Identifier')]

print(f'Found {len(log_files)} log files\n')

encodings = {}
zero_entries = []
non_zero = []
errors = []
for fpath in log_files:
    try:
        enc = _detect_encoding(fpath)
        encodings[fpath.name] = enc
        entries = list(parse_file(fpath))
        if len(entries) == 0:
            zero_entries.append(fpath.name)
        else:
            non_zero.append((fpath.name, len(entries)))
    except Exception as e:
        errors.append((fpath.name, str(e)))

print('=== Encoding per file ===')
for name, enc in sorted(encodings.items()):
    marker = ' (non-utf8)' if enc != 'utf-8' else ''
    print(f'  {name}: {enc}{marker}')

print(f'\n=== Files with entries: {len(non_zero)} ===')
for name, count in non_zero:
    print(f'  {name}: {count} entries')

print(f'\n=== Files with 0 entries: {len(zero_entries)} ===')
for name in zero_entries:
    print(f'  {name}')

if errors:
    print(f'\n=== Errors: {len(errors)} ===')
    for name, err in errors:
        print(f'  {name}: {err}')
else:
    print('\n=== No errors ===')
