import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

_CONFIG_PATH = Path(__file__).parent.parent / 'config.json'

_BASE_URL = 'https://genai-service.stage.commandcentral.com/app-gateway/api/v2'

_SYSTEM_PROMPT = (
    'You are a Wi-Fi firmware diagnostic assistant. '
    'You will receive structured anomaly reports from a log analysis tool. '
    'Provide concise, technical explanations in plain English.'
)

_FILE_PROMPT = """The following anomalous segments were detected in Wi-Fi log file: {filename}

{segments}

In 2-4 sentences, explain:
1. What the likely fault or issue is
2. Which feature(s) are the strongest evidence
3. What a developer should investigate

Be specific and technical. Do not repeat raw numbers verbatim."""


def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def _read_excerpt(path: Path) -> str:
    """Read an excerpt file and return its content."""
    try:
        return path.read_text(encoding='utf-8')
    except Exception:
        return ''


def _query(api_key: str, core_id: str, model: str, prompt: str) -> str:
    """Send a single prompt to the API and return the model's reply."""
    user_id = core_id if '@' in core_id else f'{core_id}@motorolasolutions.com'
    headers = {'x-msi-genai-api-key': api_key, 'Content-Type': 'application/json'}
    payload = {
        'userId': user_id,
        'model': model,
        'prompt': prompt,
        'system': _SYSTEM_PROMPT,
        'modelConfig': {
            'temperature': 0.3,
            'max_tokens': 2000,
        },
    }
    response = requests.post(f'{_BASE_URL}/chat', headers=headers, json=payload, timeout=60)
    if not response.ok:
        raise RuntimeError(f'{response.status_code} {response.reason}: {response.text[:500]}')
    return response.json().get('msg', '').strip()


def write_llm_report(file_data: list, cfg: dict = None):
    """
    For each anomalous file, read its segment excerpts and call the LLM to
    produce a brief plain-English explanation. Writes outputs/llm_analysis.txt.
    Credentials are loaded from .env (API_KEY, CORE_ID).
    """
    if cfg is None:
        cfg = _load_config()

    if not cfg.get('llm_enabled', False):
        return

    api_key = os.getenv('API_KEY', '')
    core_id = os.getenv('CORE_ID', '')
    model = cfg.get('llm_model', 'VertexGemini')

    if not api_key or not core_id:
        print('  Warning: llm_enabled is true but API_KEY or CORE_ID missing from .env')
        return

    output_dir = Path(cfg['output_dir'])
    excerpts_dir = output_dir / 'excerpts'

    anomalous_files = [
        fd for fd in file_data
        if fd.get('verdict') == 'ANOMALOUS'
    ]

    if not anomalous_files:
        return

    print(f'\nGenerating LLM analysis for {len(anomalous_files)} anomalous file(s)...')

    from datetime import datetime
    report_path = output_dir / 'llm_analysis.md'

    sections = []
    sections.append('# Wi-Fi Log Anomaly Analysis\n')
    sections.append(f'> Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ')
    sections.append(f'> Model: `{model}`  ')
    sections.append(f'> Files analysed: {len(anomalous_files)}\n')
    sections.append('---\n')

    for fd in anomalous_files:
        fname = fd['fpath'].name
        n_anomalous = sum(s['is_anomalous'] for s in fd['segments'])
        n_total = len(fd['segments'])
        max_score = max(s['anomaly_score'] for s in fd['segments'])

        # Collect all excerpt files for this log file
        excerpt_texts = []
        file_subdir = excerpts_dir / fname
        if file_subdir.is_dir():
            for p in sorted(file_subdir.glob('seg*.txt')):
                content = _read_excerpt(p)
                if content:
                    excerpt_texts.append(content)
        else:
            safe_name = fname.replace(' ', '_').replace('(', '').replace(')', '')
            for p in sorted(excerpts_dir.glob(f'{safe_name}_seg*.txt')):
                content = _read_excerpt(p)
                if content:
                    excerpt_texts.append(content)

        if not excerpt_texts:
            continue

        segments_block = '\n\n'.join(excerpt_texts)
        prompt = _FILE_PROMPT.format(filename=fname, segments=segments_block)

        try:
            explanation = _query(api_key, core_id, model, prompt)
            sections.append(f'## `{fname}`\n')
            sections.append(explanation)
            sections.append('\n---\n')
            print(f'  {fname}: explanation generated')
        except Exception as e:
            print(f'  Warning: LLM failed for {fname}: {e}')

    if len(sections) > 4:
        report_path.write_text('\n'.join(sections), encoding='utf-8')
        print(f'  LLM analysis saved to {report_path}')
