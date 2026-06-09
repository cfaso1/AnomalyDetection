"""
Train the rare-template detector and supporting log-parsing artifacts.

There is no ML model to train: the bug-signature library is rule-based.
What "training" produces:

  1. A Drain parse tree that maps free-form log lines to compact template
     ids (`event_id`). Fit on all known logs (normal + anomaly) so that
     scan-time template assignment is stable.
  2. A semantic template encoder so out-of-vocabulary templates seen at
     scan time can be nearest-neighbour-resolved to known templates,
     preventing spurious rare-template flags from minor wording drift.
  3. The *set of template ids that ever appeared in the normal corpus*.
     The rare-template detector at scan time will flag any template id
     that is missing from this set (and whose text contains error-hint
     words such as 'failed', 'error', 'exception').
"""
from __future__ import annotations

import json
from pathlib import Path

from src.parser import parse_file
from src.drain import DrainTree, apply_drain
from src.template_encoder import TemplateEncoder
from src.rare_template_detector import save as save_normal_event_ids

_CONFIG_PATH = Path(__file__).resolve().parent.parent / 'config.json'


def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def _list_log_files(log_dir: Path) -> list[Path]:
    return sorted(
        f for f in Path(log_dir).glob('*.log')
        if not f.name.endswith('.Zone.Identifier')
    )


def train(normal_dir: Path, anomaly_dir: Path, cfg: dict | None = None):
    """
    Fit Drain + template encoder; record the normal-corpus event_id set.

    `anomaly_dir` is used only to widen the Drain tree (so anomaly-only
    templates also get stable ids), not to influence the normal set.
    """
    if cfg is None:
        cfg = _load_config()

    model_dir = Path(cfg['model_dir'])
    model_dir.mkdir(parents=True, exist_ok=True)

    normal_files  = _list_log_files(normal_dir)
    anomaly_files = _list_log_files(anomaly_dir)
    all_files = normal_files + anomaly_files
    if not all_files:
        raise ValueError(
            f'No .log files found in {normal_dir} or {anomaly_dir}'
        )

    print('Step 1: Fitting Drain parse tree on all log files...')
    drain_tree = DrainTree(
        sim_threshold=cfg.get('drain_sim_threshold', 0.5),
        max_children=cfg.get('drain_max_children', 128),
    )
    for fpath in all_files:
        try:
            for entry in parse_file(fpath):
                drain_tree.add(entry.get('message', ''))
        except Exception as exc:
            print(f'  Warning: skipped {fpath.name}: {exc}')
    drain_tree.save(model_dir / 'drain_tree.pkl')
    print(f'  Drain templates discovered: {drain_tree._counter}')

    print('\nStep 2: Fitting semantic template encoder...')
    encoder = TemplateEncoder(
        model_name=cfg.get('semantic_model', 'all-MiniLM-L6-v2'),
        oov_min_similarity=cfg.get('oov_min_similarity', 0.55),
    )
    encoder.fit(drain_tree.all_templates())
    encoder.save(model_dir / 'template_encoder.pkl')
    print(f'  Semantic embeddings: {len(encoder.known_event_ids())} '
          f'templates -> {encoder.embedding_dim}-dim vectors')

    print('\nStep 3: Recording normal-corpus event_id set...')
    normal_event_ids: set[str] = set()
    for fpath in normal_files:
        try:
            entries = list(parse_file(fpath))
            if not entries:
                continue
            apply_drain(entries, drain_tree, frozen=True, encoder=encoder)
            for e in entries:
                eid = e.get('event_id', '')
                if eid and eid != '<unk>':
                    normal_event_ids.add(eid)
        except Exception as exc:
            print(f'  Warning: skipped {fpath.name}: {exc}')
    save_normal_event_ids(model_dir / 'normal_template_ids.pkl',
                          normal_event_ids)
    print(f'  Normal-corpus event_ids recorded: {len(normal_event_ids)}')

    print(f'\nTraining complete. Artifacts saved to {model_dir}/')
