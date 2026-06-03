#!/usr/bin/env python3
"""DAWG - Detector of Anomalous Wi-Fi Groups: dev-tool GUI for single-file anomaly analysis."""
import base64
import html as html_lib
import io
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

try:
    from tkinterweb import HtmlFrame
    import markdown as _md
    _HTML_RENDER = True
except ImportError:
    _HTML_RENDER = False

from src.detector import load_artifacts, score_file, write_excerpts, _load_config
from src.llm_reporter import write_llm_report

_LOGO_PATH = Path(__file__).parent.parent / 'DAWGLOGO.png'
_TRANS_PATH = Path(__file__).parent.parent / 'DAWGTRANS.png'


def _set_window_icon(root: tk.Tk):
    """Set the window/taskbar icon from DAWGLOGO.png."""
    if not _LOGO_PATH.exists():
        return
    try:
        from PIL import Image, ImageTk
        img = Image.open(_LOGO_PATH).resize((64, 64), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)
    except Exception:
        try:
            photo = tk.PhotoImage(file=str(_LOGO_PATH))
        except Exception:
            return
    root.iconphoto(True, photo)
    root._icon_ref = photo


def _build_watermark_uri(width: int = 320) -> str:
    """Return a base64 PNG data URI of DAWGTRANS.png scaled and faded.
    Applies a top-to-bottom gradient fade baked into the alpha channel.
    Returns empty string on any failure."""
    if not _TRANS_PATH.exists():
        return ''
    try:
        import numpy as np
        from PIL import Image
        img = Image.open(_TRANS_PATH).convert('RGBA')
        ratio = width / img.width
        img = img.resize((width, max(1, int(img.height * ratio))), Image.LANCZOS)
        r, g, b, a = img.split()
        h, w_px = img.height, img.width
        a_arr = np.array(a, dtype=np.float32)
        gradient = np.linspace(0.55, 0.15, h)[:, np.newaxis] * np.ones((1, w_px))
        a_arr = (a_arr * gradient).clip(0, 255).astype(np.uint8)
        img = Image.merge('RGBA', (r, g, b, Image.fromarray(a_arr)))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return ''


_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.6; color: #1a1a1a;
    padding: 16px 28px; background: #ffffff;
  }}
  h1 {{ font-size: 1.55em; border-bottom: 2px solid #e0e0e0; padding-bottom: 4px; margin-top: 0; }}
  h2 {{ font-size: 1.25em; color: #1a4a8a; border-bottom: 1px solid #e8e8e8; padding-bottom: 2px; }}
  h3 {{ font-size: 1.05em; color: #333; }}
  p  {{ margin: 6px 0; }}
  code {{
    background: #f3f3f3; padding: 1px 5px; border-radius: 3px;
    font-family: "Courier New", monospace; font-size: 0.88em;
  }}
  pre {{
    background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px;
    padding: 12px; font-family: "Courier New", monospace;
    font-size: 0.82em; white-space: pre-wrap; word-break: break-all;
    overflow-x: auto;
  }}
  blockquote {{
    border-left: 3px solid #bbb; margin: 4px 0 8px 0;
    padding: 3px 14px; color: #555; background: #fafafa;
  }}
  hr {{ border: none; border-top: 1px solid #ddd; margin: 18px 0; }}
  .ok   {{ color: #276749; font-size: 1.15em; font-weight: bold; }}
  .bad  {{ color: #c53030; font-size: 1.15em; font-weight: bold; }}
  .fname {{ font-family: monospace; font-size: 1em; color: #444; margin-bottom: 10px; }}
  .sec  {{ font-size: 1.1em; font-weight: bold; border-bottom: 1px solid #ccc;
           padding-bottom: 2px; margin: 22px 0 10px 0; color: #222; }}
</style>
</head>
<body>
<div style="text-align:center; padding: 12px 0 6px 0;">{wm_img}</div>
{body}
</body>
</html>"""


def _compute_verdict(scored_segments: list, cfg: dict) -> str:
    n_segs = len(scored_segments)
    if n_segs == 0:
        return 'normal'
    n_anomalous = sum(s['is_anomalous'] for s in scored_segments)
    min_fraction = cfg.get('anomaly_segment_fraction', 0.0)
    return 'ANOMALOUS' if n_anomalous > 0 and (n_anomalous / n_segs) >= min_fraction else 'normal'


def _md_to_html(text: str) -> str:
    return _md.markdown(text, extensions=['fenced_code', 'tables', 'nl2br'])


class AnomalyGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('DAWG — Detector of Anomalous Wi-Fi Groups')
        self.root.geometry('960x700')
        self.root.resizable(True, True)
        _set_window_icon(self.root)
        self._wm_uri = _build_watermark_uri()
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill='x')

        ttk.Label(top, text='Log File:').pack(side='left')
        self.file_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.file_var, width=65, state='readonly').pack(side='left', padx=5)
        ttk.Button(top, text='Browse...', command=self._browse).pack(side='left')
        self.analyze_btn = ttk.Button(top, text='Analyze', command=self._run_analysis, state='disabled')
        self.analyze_btn.pack(side='left', padx=5)

        self.status_var = tk.StringVar(value='DAWG — Detector of Anomalous Wi-Fi Groups | Select a .log file to begin.')
        ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w').pack(
            fill='x', side='bottom', padx=2, pady=2
        )

        result_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        result_frame.pack(fill='both', expand=True)

        if _HTML_RENDER:
            self.view = HtmlFrame(result_frame, messages_enabled=False)
            self.view.pack(fill='both', expand=True)
            self._render('<p style="color:#999; text-align:center;"><em>Select a .log file to begin.</em></p>', wm_width=300)
        else:
            self.view = scrolledtext.ScrolledText(
                result_frame, wrap='word', font=('Courier', 10), state='disabled'
            )
            self.view.pack(fill='both', expand=True)
            messagebox.showwarning(
                'Optional dependencies missing',
                'Install these packages for rendered markdown output:\n\n'
                '  pip install markdown tkinterweb\n\nFalling back to plain text.',
            )

    def _render(self, body: str, wm_width: int = 200):
        wm_img = f'<img src="{self._wm_uri}" width="{wm_width}" />' if self._wm_uri else ''
        self.view.load_html(_HTML_TEMPLATE.format(body=body, wm_img=wm_img))

    def _browse(self):
        path = filedialog.askopenfilename(
            title='Select Log File',
            filetypes=[('Log files', '*.log'), ('All files', '*.*')],
        )
        if path:
            self.file_var.set(path)
            self.analyze_btn.config(state='normal')
            self.status_var.set('File selected. Click Analyze to run.')

    def _run_analysis(self):
        fpath = Path(self.file_var.get())
        if not fpath.exists():
            messagebox.showerror('Error', 'File not found.')
            return
        self.analyze_btn.config(state='disabled')
        self.status_var.set('Analyzing...')
        self._display('<p><em>Running analysis&#8230;</em></p>', plain='Running analysis...\n')
        threading.Thread(target=self._analyze, args=(fpath,), daemon=True).start()

    def _analyze(self, fpath: Path):
        try:
            cfg = _load_config()
            iso, scaler, if_score_range, classifier = load_artifacts(cfg)
            scored, entries, feats = score_file(fpath, iso, scaler, if_score_range, cfg, classifier=classifier)

            if not scored:
                self.root.after(0, self._show_result, 'normal', '', [], fpath)
                return

            verdict = _compute_verdict(scored, cfg)
            file_data = [{'fpath': fpath, 'segments': scored, 'entries': entries,
                          'feats': feats, 'verdict': verdict}]

            excerpt_texts = []
            llm_text = ''

            if verdict == 'ANOMALOUS':
                write_excerpts(file_data, cfg)
                write_llm_report(file_data, cfg)

                output_dir = Path(cfg['output_dir'])
                excerpts_dir = output_dir / 'excerpts'
                fname = fpath.name
                file_subdir = excerpts_dir / fname
                if file_subdir.is_dir():
                    for p in sorted(file_subdir.glob('seg*.txt')):
                        excerpt_texts.append(p.read_text(encoding='utf-8'))
                else:
                    safe_name = fname.replace(' ', '_').replace('(', '').replace(')', '')
                    for p in sorted(excerpts_dir.glob(f'{safe_name}_seg*.txt')):
                        excerpt_texts.append(p.read_text(encoding='utf-8'))

                llm_path = output_dir / 'llm_analysis.md'
                if llm_path.exists():
                    llm_text = llm_path.read_text(encoding='utf-8')

            self.root.after(0, self._show_result, verdict, llm_text, excerpt_texts, fpath)

        except Exception as exc:
            self.root.after(0, self._show_error, str(exc))

    def _show_result(self, verdict: str, llm_text: str, excerpt_texts: list, fpath: Path):
        self.analyze_btn.config(state='normal')

        parts = [f'<p class="fname">File: <strong>{html_lib.escape(fpath.name)}</strong></p>']
        plain_parts = [f'File: {fpath.name}\n\n']

        if verdict == 'normal':
            self.status_var.set('Analysis complete: NORMAL')
            parts.append('<p class="ok">&#10003; No anomalies detected.</p>')
            plain_parts.append('No anomalies detected.\n')
        else:
            self.status_var.set('Analysis complete: ANOMALOUS')
            parts.append('<p class="bad">&#9888; ANOMALOUS</p>')
            plain_parts.append('ANOMALOUS\n\n')

            if llm_text:
                parts.append('<p class="sec">LLM Analysis</p>')
                parts.append(_md_to_html(llm_text))
                plain_parts.append('--- LLM ANALYSIS ---\n' + llm_text + '\n\n')

            if excerpt_texts:
                parts.append('<p class="sec">Anomalous Segment Details</p>')
                for txt in excerpt_texts:
                    parts.append(f'<pre>{html_lib.escape(txt)}</pre>')
                plain_parts.append('--- SEGMENT DETAILS ---\n' + '\n\n'.join(excerpt_texts))

        self._display('\n'.join(parts), plain=''.join(plain_parts))

    def _show_error(self, msg: str):
        self.analyze_btn.config(state='normal')
        self.status_var.set('Error during analysis.')
        body = f'<p style="color:red;font-weight:bold;">Error</p><pre>{html_lib.escape(msg)}</pre>'
        self._display(body, plain=f'Error:\n{msg}\n')

    def _display(self, html_body: str, plain: str = ''):
        if _HTML_RENDER:
            self._render(html_body)
        else:
            self.view.config(state='normal')
            self.view.delete('1.0', 'end')
            self.view.insert('end', plain)
            self.view.config(state='disabled')


def main():
    root = tk.Tk()
    AnomalyGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
