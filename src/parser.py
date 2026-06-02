import re
from pathlib import Path

_LOG_LINE_RE = re.compile(
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


def _extract_level(level_msg: str) -> str:
    m = _LEVEL_RE.match(level_msg.strip())
    return m.group(1) if m else 'Unknown'


def parse_file(filepath):
    """
    Yields one dict per log entry from a Motorola Solutions Wi-Fi log file.

    Each dict contains:
        abs_timestamp  : None
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

            m = _LOG_LINE_RE.match(line)
            if m:
                if current is not None:
                    yield current

                current = {
                    'abs_timestamp': None,
                    'elapsed_ms': int(float(m.group(1)) * 1000),
                    'line_num': line_num_fallback,
                    'component': m.group(3).strip(),
                    'level': _extract_level(m.group(4)),
                    'message': m.group(4).strip(),
                }
                continue

            if current is not None and raw[:1] in (' ', '\t'):
                current['message'] += '\n' + line.strip()

    if current is not None:
        yield current
