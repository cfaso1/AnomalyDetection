import re
import pickle
from pathlib import Path

_DYN_RE = re.compile(
    r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'
    r'|(?:\d{1,3}\.){3}\d{1,3}'
    r'|\b0x[0-9a-fA-F]+\b'
    r'|\b\d+(?:\.\d+)?\b'
)

_PARAM_RE = re.compile(
    r'(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})'
    r'|(?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
    r'|(?P<hex>\b0x[0-9a-fA-F]+\b)'
    r'|(?P<num>\b\d+(?:\.\d+)?\b)'
)


def _tokenize(message: str) -> list[str]:
    cleaned = _DYN_RE.sub('<*>', message)
    return cleaned.split()


def _extract_params(message: str) -> list[str]:
    return [m.group() for m in _PARAM_RE.finditer(message)]


def _sim(template: list[str], tokens: list[str]) -> float:
    if len(template) != len(tokens):
        return 0.0
    if not template:
        return 1.0
    matches = sum(1 for t, m in zip(tokens, template) if m == '<*>' or t == m)
    return matches / len(template)


def _merge(template: list[str], tokens: list[str]) -> list[str]:
    return [t if t == m else '<*>' for t, m in zip(tokens, template)]


class DrainTree:
    """
    Fixed-depth parse tree implementing the Drain log parsing algorithm.

    Groups log messages into templates by stripping dynamic tokens and
    assigning a stable Event_ID to each discovered template.
    """

    def __init__(self, sim_threshold: float = 0.5, max_children: int = 128):
        self.sim_threshold = sim_threshold
        self.max_children = max_children
        self._groups: dict[int, dict[str, list[dict]]] = {}
        self._templates: dict[str, str] = {}
        self._counter: int = 0

    def _new_event_id(self) -> str:
        eid = f'E{self._counter:04d}'
        self._counter += 1
        return eid

    def add(self, message: str) -> tuple[str, str, list[str]]:
        """
        Process one log message through the Drain tree.

        Returns:
            event_id  : stable template identifier (e.g. 'E0042')
            template  : static template string with <*> wildcards
            params    : list of dynamic values extracted from the message
        """
        tokens = _tokenize(message)
        params = _extract_params(message)
        n = len(tokens)

        prefix = tokens[0] if tokens else '<empty>'

        length_bucket = self._groups.setdefault(n, {})
        prefix_groups = length_bucket.setdefault(prefix, [])

        best_sim = -1.0
        best_group = None
        for group in prefix_groups:
            s = _sim(group['template'], tokens)
            if s > best_sim:
                best_sim = s
                best_group = group

        if best_group is not None and best_sim >= self.sim_threshold:
            best_group['template'] = _merge(best_group['template'], tokens)
            best_group['count'] += 1
            self._templates[best_group['event_id']] = ' '.join(best_group['template'])
            return best_group['event_id'], self._templates[best_group['event_id']], params

        if len(prefix_groups) < self.max_children:
            eid = self._new_event_id()
            template_str = ' '.join(tokens)
            prefix_groups.append({'template': tokens[:], 'event_id': eid, 'count': 1})
            self._templates[eid] = template_str
            return eid, template_str, params

        eid = self._new_event_id()
        wildcard = ['<*>'] * n
        template_str = ' '.join(wildcard)
        prefix_groups.append({'template': wildcard, 'event_id': eid, 'count': 1})
        self._templates[eid] = template_str
        return eid, template_str, params

    def match(self, message: str) -> tuple[str | None, str, list[str]]:
        """
        Read-only lookup: return the best-matching existing template's
        (event_id, template, params), or (None, fallback_template, params) if
        no existing template clears `sim_threshold`. Never mutates the tree.
        """
        tokens = _tokenize(message)
        params = _extract_params(message)
        n = len(tokens)
        prefix = tokens[0] if tokens else '<empty>'

        length_bucket = self._groups.get(n)
        if not length_bucket:
            return None, ' '.join(tokens), params

        prefix_groups = length_bucket.get(prefix)
        if not prefix_groups:
            return None, ' '.join(tokens), params

        best_sim = -1.0
        best_group = None
        for group in prefix_groups:
            s = _sim(group['template'], tokens)
            if s > best_sim:
                best_sim = s
                best_group = group

        if best_group is not None and best_sim >= self.sim_threshold:
            return best_group['event_id'], self._templates[best_group['event_id']], params

        return None, ' '.join(tokens), params

    def all_templates(self) -> dict[str, str]:
        """Return a copy of the {event_id: template_str} table."""
        return dict(self._templates)

    def get_template(self, event_id: str) -> str:
        return self._templates.get(event_id, event_id)

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path: Path) -> 'DrainTree':
        with open(Path(path), 'rb') as f:
            return pickle.load(f)


def apply_drain(entries: list[dict], tree: DrainTree,
                frozen: bool = False, encoder=None) -> list[dict]:
    """
    Apply Drain to a list of parsed log entries (from parser.parse_file).

    Mutates each entry in-place, adding:
        event_id          : str  (existing template id, or '<unk>' if no resolution)
        template          : str
        params            : list[str]
        resolved_via_oov  : bool (only present when set; True if encoder fallback used)
        oov_similarity    : float (only present when set)

    Modes:
        frozen=False              -> Drain may grow new templates (training).
        frozen=True, encoder=None -> Pure lookup; unmatched -> event_id='<unk>'.
        frozen=True, encoder=X    -> Lookup; on miss, resolve to nearest known
                                     event_id via semantic similarity.
    """
    for entry in entries:
        msg = entry.get('message', '')
        if not frozen:
            eid, tmpl, params = tree.add(msg)
            entry['event_id'] = eid
            entry['template'] = tmpl
            entry['params'] = params
            continue

        eid, tmpl, params = tree.match(msg)
        if eid is not None:
            entry['event_id'] = eid
            entry['template'] = tmpl
            entry['params'] = params
            continue

        # Unmatched at inference. Try semantic fallback if encoder is available.
        if encoder is not None:
            resolved_eid, sim = encoder.resolve('<unk>', tmpl)
            if resolved_eid != '<unk>':
                entry['event_id'] = resolved_eid
                entry['template'] = tree.get_template(resolved_eid)
                entry['params'] = params
                entry['resolved_via_oov'] = True
                entry['oov_similarity'] = sim
                continue

        entry['event_id'] = '<unk>'
        entry['template'] = tmpl
        entry['params'] = params
        entry['resolved_via_oov'] = False
    return entries
