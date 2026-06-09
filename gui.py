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

from src.scanner import (
    scan_file, file_verdict, write_report,
    load_config, load_model_artifacts, parse_and_tag,
)

_LOGO_PATH = Path(__file__).parent / 'DAWGLOGO.png'
_TRANS_PATH = Path(__file__).parent / 'DAWGTRANS.png'


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
            cfg = load_config()
            model_dir = Path(cfg['model_dir'])
            drain_tree, encoder = load_model_artifacts(model_dir)
            parsed = (parse_and_tag(fpath, drain_tree, encoder)
                      if drain_tree is not None else None)
            findings = scan_file(
                fpath,
                model_dir=model_dir if drain_tree is not None else None,
                parsed_entries=parsed,
            )
            verdict = file_verdict(findings)
            # Persist a Markdown + JSON report alongside the GUI display.
            try:
                out_dir = Path(cfg.get('output_dir', 'outputs')) / 'findings'
                # Clear previous outputs for this file
                stem = fpath.stem
                json_path = out_dir / 'json' / f'{stem}.findings.json'
                md_path = out_dir / 'md' / f'{stem}.findings.md'
                if json_path.exists():
                    json_path.unlink()
                if md_path.exists():
                    md_path.unlink()
                write_report(fpath, findings, out_dir)
            except Exception:
                pass
            self.root.after(0, self._show_result, verdict, findings, fpath)
        except Exception as exc:
            self.root.after(0, self._show_error, str(exc))

    def _show_result(self, verdict: str, findings: list, fpath: Path):
        self.analyze_btn.config(state='normal')

        h = html_lib
        parts = [f'<p class="fname">File: <strong>{h.escape(fpath.name)}</strong></p>']
        plain_parts = [f'File: {fpath.name}\n\n']

        verdict_class = 'ok' if verdict == 'NORMAL' else 'bad'
        verdict_icon  = '&#10003;' if verdict == 'NORMAL' else '&#9888;'
        self.status_var.set(f'Analysis complete: {verdict}')
        parts.append(f'<p class="{verdict_class}">{verdict_icon} {verdict} '
                     f'&nbsp;|&nbsp; {len(findings)} finding(s)</p>')
        plain_parts.append(f'{verdict} | {len(findings)} finding(s)\n\n')

        if not findings:
            parts.append('<p><em>No developer-actionable bugs detected.</em></p>')
            plain_parts.append('No developer-actionable bugs detected.\n')
            self._display('\n'.join(parts), plain=''.join(plain_parts))
            return

        # Severity summary banner.
        from collections import Counter
        sev_counts = Counter(f.severity for f in findings)
        summary_bits = [f'<code>{s}</code>: {sev_counts[s]}'
                        for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
                        if sev_counts.get(s)]
        parts.append('<p>' + ' &nbsp; '.join(summary_bits) + '</p>')

        for i, f in enumerate(findings, 1):
            parts.append(self._format_finding_html(i, f))
            plain_parts.append(self._format_finding_plain(i, f))

        self._display('\n'.join(parts), plain=''.join(plain_parts))

    def _severity_color(self, sev: str) -> str:
        return {
            'CRITICAL': '#c53030',
            'HIGH':     '#dd6b20',
            'MEDIUM':   '#b7791f',
            'LOW':      '#2c5282',
        }.get(sev, '#444')

    def _format_finding_html(self, i: int, f) -> str:
        h = html_lib
        color = self._severity_color(f.severity)
        out = [
            f'<h2>{i}. <span style="color:{color}">[{h.escape(f.severity)}]</span> '
            f'{h.escape(f.description)}</h2>',
            f'<p><strong>Category:</strong> {h.escape(f.category)} &nbsp;|&nbsp; '
            f'<strong>Line:</strong> {f.line_number} &nbsp;|&nbsp; '
            f'<strong>Timestamp:</strong> <code>{h.escape(f.timestamp)}</code> &nbsp;|&nbsp; '
            f'<strong>Component:</strong> <code>{h.escape(f.component)}</code> &nbsp;|&nbsp; '
            f'<strong>Actionability:</strong> {f.actionability_score:.2f}</p>',
        ]
        if f.burst_size > 1:
            out.append(f'<p><strong>Burst size:</strong> {f.burst_size} matches</p>')
        out.append('<p><strong>Trigger line:</strong></p>')
        out.append(f'<pre>{h.escape(f.trigger_line)}</pre>')
        if f.context_before or f.context_after:
            ctx = ''
            for b in f.context_before:
                ctx += '  ' + h.escape(b) + '\n'
            ctx += '&gt; ' + h.escape(f.trigger_line) + '\n'
            for a in f.context_after:
                ctx += '  ' + h.escape(a) + '\n'
            out.append('<p><strong>Context:</strong></p>')
            out.append(f'<pre>{ctx}</pre>')
        out.append('<hr />')
        return '\n'.join(out)

    def _format_finding_plain(self, i: int, f) -> str:
        lines = [
            f'\n{i}. [{f.severity}] {f.description}',
            f'   Category: {f.category} | Line {f.line_number} | TS {f.timestamp} | {f.component}',
            f'   Trigger: {f.trigger_line}',
        ]
        return '\n'.join(lines) + '\n'

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
