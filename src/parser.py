import re
from datetime import datetime
from pathlib import Path

_LOG_LINE_RE = re.compile(
    r'^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'
    r'\|(\d{3}Days \d{2}:\d{2}:\d{2}:\d{2})'
    r'\|\s*(\d+)'
    r'\|([^|]+)'
    r'\|(.+)$'
)

_LOG_LINE_RE2 = re.compile(
    r'^\[(\d+\.\d+)\]'
    r'\s+\[([^\]]+)\]'
    r'\s+\[([^\]]+)\]'
    r'\s+(.+)$'
)

_LEVEL_RE = re.compile(r'^(Level\d+|Version|Warning|Error|Debug)\s*:')

_ENCODINGS = ['utf-8', 'latin-1', 'cp1252']


def _detect_encoding(filepath: Path) -> str:
    for enc in _ENCODINGS:
        try:
            with open(filepath, encoding=enc, errors='strict') as f:
                for _ in range(200):
                    if not f.readline():
                        break
            return enc
        except UnicodeDecodeError:
            continue
    return 'latin-1'


def _parse_elapsed_ms(elapsed_str: str) -> int:
    m = re.match(r'(\d+)Days (\d+):(\d+):(\d+):(\d+)', elapsed_str)
    if not m:
        return 0
    days, h, minutes, s, cs = (int(x) for x in m.groups())
    return (days * 86400 + h * 3600 + minutes * 60 + s) * 1000 + cs * 10


def _extract_level(level_msg: str) -> str:
    m = _LEVEL_RE.match(level_msg.strip())
    return m.group(1) if m else 'Unknown'


def parse_file(filepath):
    """
    Yields one dict per log entry from a Motorola Solutions Wi-Fi log file.

    Each dict contains:
        abs_timestamp  : datetime
        elapsed_ms     : int   (milliseconds since session start)
        line_num       : int
        component      : str   ('SSPLogger', 'Networking', ...)
        level          : str   ('Level6', 'Level8', 'Version', 'Warning', ...)
        message        : str   (full message text including continuation lines)
    """
    filepath = Path(filepath)
    enc = _detect_encoding(filepath)

    current = None
    line_num_fallback = 0

    with open(filepath, encoding=enc, errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            line_num_fallback += 1

            m1 = _LOG_LINE_RE.match(line)
            if m1:
                if current is not None:
                    yield current

                try:
                    abs_ts = datetime.strptime(m1.group(1), '%m/%d/%Y %H:%M:%S')
                except ValueError:
                    abs_ts = None

                current = {
                    'abs_timestamp': abs_ts,
                    'elapsed_ms': _parse_elapsed_ms(m1.group(2)),
                    'line_num': int(m1.group(3)),
                    'component': m1.group(4).strip(),
                    'level': _extract_level(m1.group(5)),
                    'message': m1.group(5).strip(),
                    'format': 1,
                }
                continue

            m2 = _LOG_LINE_RE2.match(line)
            if m2:
                if current is not None:
                    yield current

                current = {
                    'abs_timestamp': None,
                    'elapsed_ms': int(float(m2.group(1)) * 1000),
                    'line_num': line_num_fallback,
                    'component': m2.group(3).strip(),
                    'level': _extract_level(m2.group(4)),
                    'message': m2.group(4).strip(),
                    'format': 2,
                }
                continue

            if current is not None and raw[:1] in (' ', '\t'):
                current['message'] += '\n' + line.strip()

    if current is not None:
        yield current
