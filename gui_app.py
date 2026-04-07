"""
E-BOX RE Tool — Main GUI Application
Dark hacker aesthetic · 5 tabs · Thread-safe · GTX 850M optimised
"""

from __future__ import annotations
import os, sys, threading, queue, time, traceback, tempfile, subprocess
from datetime import datetime
from typing import Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ── Local imports ─────────────────────────────────────────────────────────────
try:
    from medical_unit       import MedicalUnit, Severity, HealthEvent
    from binary_parser      import parse_binary, section_summary, entropy_prefilter, calc_entropy
    from ebox512_pipeline   import EBox512, ScanResult, MalwareDetector, MalwareScanResult, GPU_AVAILABLE, cp
    from decompiler_engine  import decompile
    from apk_analyzer       import APKAnalyzer, analyze_apk_from_bytes
    from anticheat_detector import AntiCheatDetector, RiskLevel
    from gui_enhancements   import (
        ContextMenu, AdvancedProgressBar, DecompileContextMenu,
        make_text_copyable, AnalysisProgressTracker, Toast
    )
    from apk_gui_tab        import APKAnalysisTab
    from anticheat_gui_tab  import AntiCheatTab
    from apk_context        import global_apk_context
except ImportError as e:
    # Allow partial startup so user sees the error in the GUI
    print(f"[WARN] Import error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Theme constants — Hacker Dark
# ─────────────────────────────────────────────────────────────────────────────

C_BG       = "#0d1117"   # Deep dark background
C_BG2      = "#161b22"   # Panel background
C_BG3      = "#1f2937"   # Widget background
C_FG       = "#e6edf3"   # Primary text
C_FG2      = "#8b949e"   # Secondary / dimmed text
C_GREEN    = "#3fb950"   # Success / confirmed
C_CYAN     = "#58a6ff"   # Accent / headers
C_ORANGE   = "#f0883e"   # Warning
C_RED      = "#f85149"   # Error
C_YELLOW   = "#e3b341"   # Highlight / candidate
C_PURPLE   = "#bc8cff"   # Encrypted marker
C_MONO     = "Consolas"  # Monospace font
C_MONO_SZ  = 10
C_TITLE_SZ = 13


def _mono(size: int = C_MONO_SZ, style: str = '') -> tuple:
    if style:
        return (C_MONO, size, style)
    return (C_MONO, size)


# ─────────────────────────────────────────────────────────────────────────────
#  Utility widgets
# ─────────────────────────────────────────────────────────────────────────────

class ColourText(tk.Text):
    """Text widget with tag-based colour helpers."""

    TAGS = {
        'header':     {'foreground': C_CYAN,   'font': (C_MONO, C_MONO_SZ, 'bold')},
        'ok':         {'foreground': C_GREEN},
        'warn':       {'foreground': C_ORANGE},
        'error':      {'foreground': C_RED},
        'candidate':  {'foreground': C_YELLOW},
        'encrypted':  {'foreground': C_PURPLE},
        'compressed': {'foreground': C_CYAN},
        'confirmed':  {'foreground': C_GREEN,  'font': (C_MONO, C_MONO_SZ, 'bold')},
        'dim':        {'foreground': C_FG2},
        'normal':     {'foreground': C_FG},
        'addr':       {'foreground': C_CYAN},
        'mnemonic':   {'foreground': C_ORANGE},
        'operand':    {'foreground': C_FG},
        'comment':    {'foreground': C_FG2,    'font': (C_MONO, C_MONO_SZ, 'italic')},
    }

    def __init__(self, master, **kw):
        kw.setdefault('bg',             C_BG3)
        kw.setdefault('fg',             C_FG)
        kw.setdefault('insertbackground', C_FG)
        kw.setdefault('font',           _mono())
        kw.setdefault('relief',         'flat')
        kw.setdefault('bd',             0)
        kw.setdefault('wrap',           'none')
        super().__init__(master, **kw)
        for tag, cfg in self.TAGS.items():
            self.tag_configure(tag, **cfg)
        
        # Add context menu for copy functionality
        self._context_menu = ContextMenu(self)
        self.bind('<Button-3>', self._on_right_click)
        self.bind('<Control-Button-1>', self._on_right_click)
    
    def _on_right_click(self, event):
        """Handle right-click context menu."""
        if not hasattr(self, '_context_menu'):
            return
        self._context_menu.show(event, self)

    def append(self, text: str, tag: str = 'normal'):
        self.configure(state='normal')
        self.insert('end', text, tag)
        self.configure(state='disabled')

    def clear(self):
        self.configure(state='normal')
        self.delete('1.0', 'end')
        self.configure(state='disabled')

    def set_text(self, text: str, tag: str = 'normal'):
        self.clear()
        self.append(text, tag)


def _scrolled_colour_text(parent, **kw) -> ColourText:
    """Return a ColourText inside a scrollable frame."""
    frame = tk.Frame(parent, bg=C_BG2)
    frame.pack(fill='both', expand=True)

    sb_y = tk.Scrollbar(frame, orient='vertical',
                         bg=C_BG3, troughcolor=C_BG2, bd=0)
    sb_x = tk.Scrollbar(frame, orient='horizontal',
                         bg=C_BG3, troughcolor=C_BG2, bd=0)
    txt = ColourText(frame,
                     yscrollcommand=sb_y.set,
                     xscrollcommand=sb_x.set, **kw)
    sb_y.config(command=txt.yview)
    sb_x.config(command=txt.xview)

    sb_y.pack(side='right', fill='y')
    sb_x.pack(side='bottom', fill='x')
    txt.pack(side='left', fill='both', expand=True)
    return txt


class StatusBar(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=C_BG2, height=24, **kw)
        self._var = tk.StringVar(value="Ready")
        self._gpu = tk.StringVar(value="")
        tk.Label(self, textvariable=self._var,
                 bg=C_BG2, fg=C_FG2,
                 font=_mono(9), anchor='w').pack(side='left', padx=8)
        tk.Label(self, textvariable=self._gpu,
                 bg=C_BG2, fg=C_GREEN,
                 font=_mono(9), anchor='e').pack(side='right', padx=8)
        self.pack(side='bottom', fill='x')

    def set(self, msg: str, colour: str = C_FG2):
        self._var.set(msg)

    def set_gpu(self, msg: str):
        self._gpu.set(msg)


# ─────────────────────────────────────────────────────────────────────────────
#  Individual tabs
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisTab(tk.Frame):
    """Tab 1: File load, E-BOX pipeline, scan results."""

    def __init__(self, master, app: 'REToolApp', **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self._build()

    def _build(self):
        # ── Top bar ──────────────────────────────────────────
        top = tk.Frame(self, bg=C_BG2, pady=6, padx=8)
        top.pack(fill='x', side='top')

        tk.Label(top, text="📂 Target File:",
                 bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left')
        self._path_var = tk.StringVar(value="<no file loaded>")
        tk.Label(top, textvariable=self._path_var,
                 bg=C_BG2, fg=C_CYAN, font=_mono(9),
                 width=55, anchor='w').pack(side='left', padx=6)

        btn_kw = dict(bg=C_BG3, fg=C_FG, relief='flat',
                      activebackground=C_CYAN, activeforeground=C_BG,
                      font=_mono(9), padx=10, pady=3, cursor='hand2')
        tk.Button(top, text="Open",  command=self.app.open_file,  **btn_kw).pack(side='left', padx=2)
        tk.Button(top, text="Scan",  command=self.app.start_scan, **btn_kw).pack(side='left', padx=2)
        tk.Button(top, text="🦠 Malware", command=self.app.start_malware_analysis, **btn_kw).pack(side='left', padx=2)
        tk.Button(top, text="Clear", command=self._clear,          **btn_kw).pack(side='left', padx=2)

        # ── Config row ───────────────────────────────────────
        cfg = tk.Frame(self, bg=C_BG2, pady=4, padx=8)
        cfg.pack(fill='x', side='top')

        tk.Label(cfg, text="Window:", bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left')
        self._win_var = tk.StringVar(value="512")
        win_combo = ttk.Combobox(cfg, textvariable=self._win_var,
                                 values=["256", "512", "1024", "2048"],
                                 width=6, state='readonly')
        win_combo.pack(side='left', padx=4)

        tk.Label(cfg, text="Step:", bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left', padx=(10, 0))
        self._step_var = tk.StringVar(value="256")
        step_combo = ttk.Combobox(cfg, textvariable=self._step_var,
                                  values=["128", "256", "512"],
                                  width=6, state='readonly')
        step_combo.pack(side='left', padx=4)

        # ── Progress bar ─────────────────────────────────────
        prog_frame = tk.Frame(self, bg=C_BG2, pady=4, padx=8)
        prog_frame.pack(fill='x', side='top')
        self._prog_var = tk.DoubleVar(value=0.0)
        self._prog_lbl = tk.StringVar(value="Idle")
        prog = ttk.Progressbar(prog_frame, variable=self._prog_var,
                               maximum=100, length=400, mode='determinate')
        prog.pack(side='left')
        tk.Label(prog_frame, textvariable=self._prog_lbl,
                 bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left', padx=8)

        # ── Paned split: summary | scan results ──────────────
        pane = tk.PanedWindow(self, orient='horizontal',
                               bg=C_BG, sashwidth=4, sashrelief='flat')
        pane.pack(fill='both', expand=True, padx=4, pady=4)

        # Left: file / parse summary
        left = tk.Frame(pane, bg=C_BG2)
        tk.Label(left, text="⚙ File Summary",
                 bg=C_BG2, fg=C_CYAN, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=4)
        self._summary_txt = _scrolled_colour_text(left, height=20)
        pane.add(left, minsize=280)

        # Right: E-BOX scan output
        right = tk.Frame(pane, bg=C_BG2)
        tk.Label(right, text="🔬 E-BOX 512 V3.2 — Scan Output",
                 bg=C_BG2, fg=C_CYAN, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=4)
        self._scan_txt = _scrolled_colour_text(right, height=20)
        pane.add(right, minsize=350)

    def update_path(self, path: str):
        self._path_var.set(os.path.basename(path))

    def update_progress(self, pct: float, msg: str):
        self._prog_var.set(pct)
        self._prog_lbl.set(msg)

    def append_summary(self, text: str, tag: str = 'normal'):
        self._summary_txt.append(text, tag)

    def append_scan(self, text: str, tag: str = 'normal'):
        self._scan_txt.append(text, tag)

    def clear_summary(self):
        self._summary_txt.clear()

    def clear_scan(self):
        self._scan_txt.clear()

    def _clear(self):
        self.clear_summary()
        self.clear_scan()
        self._prog_var.set(0.0)
        self._prog_lbl.set("Idle")

    @property
    def window_size(self) -> int:
        try:
            return int(self._win_var.get())
        except ValueError:
            return 512

    @property
    def step_size(self) -> int:
        try:
            return int(self._step_var.get())
        except ValueError:
            return 256


class StructureTab(tk.Frame):
    """Tab 2: Binary structure — sections, symbols, imports."""

    def __init__(self, master, app: 'REToolApp', **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self._build()

    def _build(self):
        pane = tk.PanedWindow(self, orient='horizontal',
                               bg=C_BG, sashwidth=4)
        pane.pack(fill='both', expand=True, padx=4, pady=4)

        # ── Sections tree ─────────────────────────────────────
        left = tk.Frame(pane, bg=C_BG2)
        tk.Label(left, text="📋 Sections",
                 bg=C_BG2, fg=C_CYAN, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=4)

        cols = ('name', 'offset', 'size', 'entropy')
        self._tree = ttk.Treeview(left, columns=cols, show='headings',
                                   selectmode='browse')
        for col, w, label in zip(
                cols, [140, 100, 100, 100],
                ['Name', 'Offset', 'Size', 'Entropy']):
            self._tree.heading(col, text=label)
            self._tree.column(col, width=w, anchor='w')

        sb = tk.Scrollbar(left, orient='vertical', command=self._tree.yview,
                           bg=C_BG3, troughcolor=C_BG2, bd=0)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)
        pane.add(left, minsize=300)

        # ── Symbols + imports ─────────────────────────────────
        right = tk.Frame(pane, bg=C_BG2)
        right_nb = ttk.Notebook(right)
        right_nb.pack(fill='both', expand=True)

        sym_frame = tk.Frame(right_nb, bg=C_BG2)
        self._sym_txt = _scrolled_colour_text(sym_frame)
        right_nb.add(sym_frame, text='Symbols')

        imp_frame = tk.Frame(right_nb, bg=C_BG2)
        self._imp_txt = _scrolled_colour_text(imp_frame)
        right_nb.add(imp_frame, text='Imports / Deps')

        emb_frame = tk.Frame(right_nb, bg=C_BG2)
        self._emb_txt = _scrolled_colour_text(emb_frame)
        right_nb.add(emb_frame, text='Embedded Regions')

        str_frame = tk.Frame(right_nb, bg=C_BG2)
        self._str_txt = _scrolled_colour_text(str_frame)
        right_nb.add(str_frame, text='Strings')

        pane.add(right, minsize=350)

        # Style treeview
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Treeview',
                        background=C_BG3, fieldbackground=C_BG3,
                        foreground=C_FG, font=_mono(),
                        rowheight=20)
        style.configure('Treeview.Heading',
                        background=C_BG2, foreground=C_CYAN,
                        font=_mono(9, 'bold'))
        style.map('Treeview', background=[('selected', C_CYAN)],
                  foreground=[('selected', C_BG)])

    def populate(self, parse_result):
        # Clear
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._sym_txt.clear()
        self._imp_txt.clear()
        self._emb_txt.clear()
        self._str_txt.clear()

        # Sections
        for sec in parse_result.sections:
            ent = f"{sec.entropy:.3f}"
            tag = ''
            if sec.entropy > 7.5:
                tag = 'encrypted'
            elif sec.entropy < 3.0:
                tag = 'ok'
            self._tree.insert('', 'end', values=(
                sec.name,
                f"0x{sec.offset:08x}",
                f"{sec.size:,}",
                ent
            ), tags=(tag,))

        self._tree.tag_configure('encrypted', foreground=C_PURPLE)
        self._tree.tag_configure('ok',        foreground=C_FG2)

        # Symbols
        if parse_result.symbols:
            self._sym_txt.append(
                f"  {'Address':>12}  {'Size':>8}  {'Type':<12}  Name\n", 'header')
            self._sym_txt.append("  " + "─" * 60 + "\n", 'dim')
            for sym in parse_result.symbols[:500]:
                self._sym_txt.append(
                    f"  0x{sym.address:010x}  {sym.size:>8,}  {sym.kind:<12}  ", 'addr')
                self._sym_txt.append(f"{sym.name}\n", 'normal')
        else:
            self._sym_txt.append("  No symbol table.\n", 'dim')

        # Imports
        if parse_result.imports:
            self._imp_txt.append("  Shared library dependencies:\n\n", 'header')
            for lib in parse_result.imports:
                self._imp_txt.append(f"  → {lib}\n", 'normal')
        else:
            self._imp_txt.append("  No dynamic imports found.\n", 'dim')

        # Embedded
        if parse_result.embedded:
            self._emb_txt.append(
                f"  {'Offset':>10}  {'Kind':<14}  {'Entropy':>8}  Status\n", 'header')
            self._emb_txt.append("  " + "─" * 60 + "\n", 'dim')
            for e in parse_result.embedded:
                status = "✓ decompressed" if e.decompressed_data else "raw"
                tag = 'ok' if e.decompressed_data else 'warn'
                self._emb_txt.append(
                    f"  0x{e.offset:08x}  {e.kind:<14}  {e.entropy:8.3f}  ", 'addr')
                self._emb_txt.append(f"{status}\n", tag)
        else:
            self._emb_txt.append("  No embedded regions found.\n", 'dim')

        # Strings
        if parse_result.strings:
            self._str_txt.append(
                f"  {len(parse_result.strings)} strings extracted:\n\n", 'header')
            for s in parse_result.strings[:500]:
                self._str_txt.append(f"  {s}\n", 'normal')
        else:
            self._str_txt.append("  No strings.\n", 'dim')

        if getattr(parse_result, 'deobfuscated_strings', None):
            self._str_txt.append("\n  Deobfuscated / decoded candidates:\n\n", 'header')
            for s in parse_result.deobfuscated_strings[:300]:
                self._str_txt.append(f"  {s}\n", 'candidate')


class DisasmTab(tk.Frame):
    """Tab 3: Disassembly (ASM) and Pseudo-C side-by-side."""

    def __init__(self, master, app: 'REToolApp', **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self._build()

    def _build(self):
        # ── Controls ──────────────────────────────────────────
        ctrl = tk.Frame(self, bg=C_BG2, pady=4, padx=8)
        ctrl.pack(fill='x', side='top')

        btn_kw = dict(bg=C_BG3, fg=C_FG, relief='flat',
                      activebackground=C_CYAN, activeforeground=C_BG,
                      font=_mono(9), padx=10, pady=3, cursor='hand2')
        tk.Button(ctrl, text="▶ Decompile", command=self.app.start_decompile,
                  **btn_kw).pack(side='left', padx=2)

        tk.Label(ctrl, text="Arch:", bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left', padx=(10, 0))
        self._arch_var = tk.StringVar(value="auto")
        arch_combo = ttk.Combobox(ctrl, textvariable=self._arch_var,
                                  values=['auto', 'x86_64', 'x86', 'ARM', 'AArch64', 'MIPS', 'PPC', 'SPARC', 'RISCV'],
                                  width=8, state='readonly')
        arch_combo.pack(side='left', padx=4)

        tk.Label(ctrl, text="Start Offset:", bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left', padx=(10, 0))
        self._start_offset_var = tk.StringVar(value="")
        start_entry = tk.Entry(ctrl, textvariable=self._start_offset_var, width=10, font=_mono(9))
        start_entry.pack(side='left', padx=4)

        tk.Label(ctrl, text="End Offset:", bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left', padx=(10, 0))
        self._end_offset_var = tk.StringVar(value="")
        end_entry = tk.Entry(ctrl, textvariable=self._end_offset_var, width=10, font=_mono(9))
        end_entry.pack(side='left', padx=4)

        self._func_var = tk.StringVar(value="All functions")
        self._func_combo = ttk.Combobox(ctrl, textvariable=self._func_var,
                                        values=['All functions'],
                                        width=26, state='readonly')
        self._func_combo.pack(side='left', padx=4)
        self._func_combo.bind('<<ComboboxSelected>>', self._on_func_select)

        # ── Split pane: ASM | Pseudo-C ────────────────────────
        pane = tk.PanedWindow(self, orient='horizontal',
                               bg=C_BG, sashwidth=4)
        pane.pack(fill='both', expand=True, padx=4, pady=4)

        left = tk.Frame(pane, bg=C_BG2)
        tk.Label(left, text="⚙ Assembly",
                 bg=C_BG2, fg=C_ORANGE, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=2)
        self._asm_txt = _scrolled_colour_text(left)
        pane.add(left, minsize=300)

        right = tk.Frame(pane, bg=C_BG2)
        tk.Label(right, text="🖥 Pseudo-C",
                 bg=C_BG2, fg=C_GREEN, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=2)
        self._c_txt = _scrolled_colour_text(right)
        pane.add(right, minsize=300)

        self._decompile_result = None

    def _load_from_disk(self, path: Optional[str]) -> str:
        if not path:
            return ''
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception:
            return ''

    def populate(self, decomp_result):
        self._decompile_result = decomp_result
        self._asm_txt.clear()
        self._c_txt.clear()

        if not decomp_result:
            return

        asm_body = decomp_result.asm_text
        if not asm_body and getattr(decomp_result, 'asm_path', None):
            asm_body = self._load_from_disk(decomp_result.asm_path)

        c_body = decomp_result.pseudo_c
        if not c_body and getattr(decomp_result, 'pseudo_c_path', None):
            c_body = self._load_from_disk(decomp_result.pseudo_c_path)

        # Coloured ASM output
        for line in asm_body.splitlines():
            if line.startswith(';;'):
                self._asm_txt.append(line + '\n', 'header')
            elif '0x' in line[:10]:
                # address  hex  mnemonic  operand
                parts = line.split(None, 3)
                if len(parts) >= 3:
                    self._asm_txt.append(parts[0] + '  ', 'addr')
                    self._asm_txt.append(parts[1] + '  ', 'dim')
                    self._asm_txt.append(parts[2] + '  ', 'mnemonic')
                    rest = parts[3] if len(parts) > 3 else ''
                    if ';' in rest:
                        code, cmt = rest.split(';', 1)
                        self._asm_txt.append(code, 'operand')
                        self._asm_txt.append('; ' + cmt + '\n', 'comment')
                    else:
                        self._asm_txt.append(rest + '\n', 'operand')
                else:
                    self._asm_txt.append(line + '\n', 'normal')
            else:
                self._asm_txt.append(line + '\n', 'dim')

        # Pseudo-C
        for line in c_body.splitlines():
            if line.startswith('/*') or line.startswith(' *') or line.startswith(' */'):
                self._c_txt.append(line + '\n', 'comment')
            elif line.startswith('#'):
                self._c_txt.append(line + '\n', 'encrypted')
            elif 'void*' in line or 'void ' in line:
                self._c_txt.append(line + '\n', 'header')
            elif '//' in line:
                idx = line.index('//')
                self._c_txt.append(line[:idx], 'normal')
                self._c_txt.append(line[idx:] + '\n', 'comment')
            elif line.strip().startswith('if '):
                self._c_txt.append(line + '\n', 'warn')
            elif 'goto' in line:
                self._c_txt.append(line + '\n', 'candidate')
            else:
                self._c_txt.append(line + '\n', 'normal')

        self._asm_txt.see('end')
        self._c_txt.see('end')

        # Update function combo
        if decomp_result.functions:
            fn_names = ['All functions'] + [f.name for f in decomp_result.functions[:200]]
            self._func_combo['values'] = fn_names

    def _on_func_select(self, event=None):
        if not self._decompile_result:
            return
        sel = self._func_var.get()
        if sel == 'All functions':
            return
        # Scroll ASM to function address
        for fn in self._decompile_result.functions:
            if fn.name == sel:
                target = f"0x{fn.start_addr:08x}"
                idx = self._asm_txt.search(target, '1.0', 'end')
                if idx:
                    self._asm_txt.configure(state='normal')
                    self._asm_txt.see(idx)
                    self._asm_txt.configure(state='disabled')

    @property
    def arch(self) -> str:
        v = self._arch_var.get()
        return None if v == 'auto' else v

    @property
    def start_offset(self) -> Optional[int]:
        v = self._start_offset_var.get().strip()
        if not v:
            return None
        try:
            return int(v, 0)  # Support 0x prefix
        except ValueError:
            return None

    @property
    def end_offset(self) -> Optional[int]:
        v = self._end_offset_var.get().strip()
        if not v:
            return None
        try:
            return int(v, 0)  # Support 0x prefix
        except ValueError:
            return None


class MedicalTab(tk.Frame):
    """Tab 4: Medical unit health dashboard + event log."""

    def __init__(self, master, app: 'REToolApp', **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self._build()

    def _build(self):
        # ── Toolbar ───────────────────────────────────────────
        tb = tk.Frame(self, bg=C_BG2, pady=4, padx=8)
        tb.pack(fill='x', side='top')

        btn_kw = dict(bg=C_BG3, fg=C_FG, relief='flat',
                      activebackground=C_RED, activeforeground=C_BG,
                      font=_mono(9), padx=10, pady=3, cursor='hand2')
        tk.Button(tb, text="🔄 Refresh",
                  command=self._refresh, **btn_kw).pack(side='left', padx=2)
        tk.Button(tb, text="📊 Correlate",
                  command=self._correlate, **btn_kw).pack(side='left', padx=2)
        tk.Button(tb, text="📋 Full Report",
                  command=self._full_report, **btn_kw).pack(side='left', padx=2)

        # ── Pane ─────────────────────────────────────────────
        pane = tk.PanedWindow(self, orient='horizontal',
                               bg=C_BG, sashwidth=4)
        pane.pack(fill='both', expand=True, padx=4, pady=4)

        # Module health panel
        left = tk.Frame(pane, bg=C_BG2)
        tk.Label(left, text="🏥 Module Health",
                 bg=C_BG2, fg=C_GREEN, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=4)
        self._health_txt = _scrolled_colour_text(left)
        pane.add(left, minsize=280)

        # Event log
        right = tk.Frame(pane, bg=C_BG2)
        tk.Label(right, text="📟 Event Log",
                 bg=C_BG2, fg=C_ORANGE, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=4)
        self._log_txt = _scrolled_colour_text(right)
        pane.add(right, minsize=350)

    def on_health_event(self, event: HealthEvent):
        """Called from MedicalUnit via listener callback."""
        tag_map = {
            Severity.OK:       'ok',
            Severity.WARNING:  'warn',
            Severity.ERROR:    'error',
            Severity.CRITICAL: 'error',
            Severity.RECOVERED:'candidate',
        }
        tag  = tag_map.get(event.severity, 'normal')
        icon = {'OK':'✅','WARNING':'⚠️','ERROR':'❌',
                'CRITICAL':'🚨','RECOVERED':'🔧'}.get(event.severity.value, '?')
        line = f"[{event.timestamp}] {icon} [{event.module}] {event.message}\n"
        self._log_txt.append(line, tag)

    def _refresh(self):
        mu = self.app.medical_unit
        self._health_txt.clear()
        self._health_txt.append("  MODULE HEALTH DASHBOARD\n", 'header')
        self._health_txt.append("  " + "─" * 50 + "\n", 'dim')
        for name, mod in mu.module_health.items():
            tag = 'ok' if mod.status == Severity.OK else \
                  'warn' if mod.status == Severity.WARNING else \
                  'error'
            self._health_txt.append(f"  {mod.summary()}\n", tag)

        healthy = mu.is_healthy()
        status  = "✅ All systems operational" if healthy else "⚠️  Issues detected"
        self._health_txt.append(f"\n  {status}\n",
                                 'ok' if healthy else 'warn')

    def _correlate(self):
        mu = self.app.medical_unit
        result = mu.cross_correlate()
        self._health_txt.clear()
        self._health_txt.append(result + "\n", 'normal')

    def _full_report(self):
        mu = self.app.medical_unit
        self._health_txt.clear()
        self._health_txt.set_text(mu.full_report(), 'normal')


class ReportTab(tk.Frame):
    """Tab 5: Full merged analysis report."""

    def __init__(self, master, app: 'REToolApp', **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=C_BG2, pady=4, padx=8)
        ctrl.pack(fill='x', side='top')

        btn_kw = dict(bg=C_BG3, fg=C_FG, relief='flat',
                      activebackground=C_CYAN, activeforeground=C_BG,
                      font=_mono(9), padx=10, pady=3, cursor='hand2')
        tk.Button(ctrl, text="Generate Report",
                  command=self._generate, **btn_kw).pack(side='left', padx=2)
        tk.Button(ctrl, text="Save to file…",
                  command=self._save, **btn_kw).pack(side='left', padx=2)

        inner = tk.Frame(self, bg=C_BG2)
        inner.pack(fill='both', expand=True, padx=4, pady=4)
        tk.Label(inner, text="📝 Analysis Report",
                 bg=C_BG2, fg=C_CYAN, font=_mono(C_TITLE_SZ, 'bold'),
                 anchor='w').pack(fill='x', padx=4, pady=4)
        self._txt = _scrolled_colour_text(inner)

    def _generate(self):
        app = self.app
        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║          E-BOX 512 V3.2 — Analysis Report               ║",
            f"║  File: {(app._current_file or 'N/A'):<52}║",
            f"║  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
        ]

        if app._parse_result:
            lines.append("── BINARY STRUCTURE ──────────────────────────────────")
            lines.append(section_summary(app._parse_result))
            lines.append("")

        if app._scan_result:
            lines.append("── E-BOX PIPELINE RESULTS ────────────────────────────")
            lines.append(EBox512.summary_text(app._scan_result))
            lines.append("")

            # Entropy prefilter analysis
            if app._parse_result and app._parse_result.sections:
                buckets = entropy_prefilter(app._parse_result)
                lines.append("── ENTROPY CLASSIFICATION ────────────────────────────")
                lines.append(f"  Low  entropy sections (H < 3.0): {len(buckets['low'])}")
                for s in buckets['low']:
                    lines.append(f"    {s.name:<20} H={s.entropy:.3f}")
                lines.append(f"  Mid  entropy sections            : {len(buckets['mid'])}")
                lines.append(f"  High entropy sections (H > 7.5)  : {len(buckets['high'])}")
                for s in buckets['high']:
                    lines.append(f"    {s.name:<20} H={s.entropy:.3f}  ← encrypted/compressed")
                lines.append("")

            # Correlations
            if app._scan_result.encrypted_regions and app._parse_result:
                corrs = EBox512.correlate_encrypted_with_sections(
                    app._scan_result, app._parse_result.sections)
                if corrs:
                    lines.append("── ENCRYPTED↔SECTION CORRELATION ─────────────────────")
                    for c in corrs[:20]:
                        lines.append(
                            f"  0x{c['enc_offset']:08x}  section={c['section']:<20}"
                            f"  H={c['H']:.2f}")
                    lines.append("")

        if app._decomp_result:
            lines.append("── DECOMPILATION SUMMARY ─────────────────────────────")
            lines.append(f"  Architecture : {app._decomp_result.arch}")
            lines.append(f"  Instructions : {len(app._decomp_result.instructions)}")
            lines.append(f"  Functions    : {len(app._decomp_result.functions)}")
            lines.append(f"  Strings      : {len(app._decomp_result.strings)}")
            if app._decomp_result.errors:
                lines.append("  Errors:")
                for e in app._decomp_result.errors:
                    lines.append(f"    {e}")
            lines.append("")

        lines.append(app.medical_unit.full_report())
        self._txt.set_text("\n".join(lines), 'normal')

    def _save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Report")
        if path:
            try:
                content = self._txt.get('1.0', 'end')
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Report saved to:\n{path}")
            except Exception as ex:
                messagebox.showerror("Error", str(ex))


# ─────────────────────────────────────────────────────────────────────────────
#  Main Application
# ─────────────────────────────────────────────────────────────────────────────

class REToolApp:
    """
    E-BOX RE Tool — Main Application Controller.
    Orchestrates all tabs, threads, and the Medical Unit.
    """

    APP_TITLE   = "E-BOX 512 RE Tool  v3.2"
    MIN_W, MIN_H = 1150, 720

    def __init__(self):
        self.medical_unit   = MedicalUnit()
        self._current_file  : Optional[str]  = None
        self._current_data  : Optional[bytes] = None
        self._parse_result  = None
        self._scan_result   = None
        self._decomp_result = None
        self._malware_result = None
        self._q: queue.Queue = queue.Queue()
        self._busy = False
        # APK analyzer state (set when APK analysis completes)
        self._apk_analyzer: Optional[object] = None
        self._apk_extract_dir: Optional[str] = None

        self._build_root()
        self._build_menu()
        self._build_notebook()
        self._build_statusbar()

        # Wire medical unit → medical tab
        self.medical_unit.add_listener(self._on_health_event_gui)

        # GPU detection display
        self._show_gpu_status()

        # Start queue poller
        self._root.after(100, self._poll_queue)

    # ── Root window ──────────────────────────────────────────────────────────

    def _build_root(self):
        self._root = tk.Tk()
        self._root.title(self.APP_TITLE)
        self._root.minsize(self.MIN_W, self.MIN_H)
        self._root.configure(bg=C_BG)
        try:
            self._root.state('zoomed')   # Maximise on Windows
        except Exception:
            self._root.geometry(f"{self.MIN_W}x{self.MIN_H}")

        # Title banner
        banner = tk.Frame(self._root, bg=C_BG2, pady=6)
        banner.pack(fill='x', side='top')
        tk.Label(banner,
                 text="◈  E-BOX 512 V3.2   Deterministic Binary Analysis System",
                 bg=C_BG2, fg=C_CYAN,
                 font=(C_MONO, 14, 'bold')).pack(side='left', padx=16)
        tk.Label(banner,
                 text="by Omsin",
                 bg=C_BG2, fg=C_FG2,
                 font=_mono(9)).pack(side='right', padx=16)

    def _build_menu(self):
        menu = tk.Menu(self._root, bg=C_BG2, fg=C_FG,
                       activebackground=C_CYAN, activeforeground=C_BG,
                       relief='flat', bd=0)
        self._root.config(menu=menu)

        fm = tk.Menu(menu, tearoff=0, bg=C_BG2, fg=C_FG,
                     activebackground=C_CYAN, activeforeground=C_BG)
        menu.add_cascade(label="File", menu=fm)
        fm.add_command(label="Open…",    command=self.open_file,      accelerator="Ctrl+O")
        fm.add_command(label="Scan",     command=self.start_scan,     accelerator="F5")
        fm.add_command(label="Decompile",command=self.start_decompile,accelerator="F6")
        fm.add_separator()
        fm.add_command(label="Exit",     command=self._root.quit)

        self._root.bind('<Control-o>', lambda e: self.open_file())
        self._root.bind('<F5>',        lambda e: self.start_scan())
        self._root.bind('<F6>',        lambda e: self.start_decompile())

    def _build_notebook(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook',         background=C_BG2, borderwidth=0)
        style.configure('TNotebook.Tab',
                        background=C_BG3, foreground=C_FG2,
                        font=_mono(10), padding=[14, 5])
        style.map('TNotebook.Tab',
                  background=[('selected', C_BG2)],
                  foreground=[('selected', C_CYAN)])

        nb = ttk.Notebook(self._root)
        nb.pack(fill='both', expand=True, padx=6, pady=(4, 0))

        self.tab_analysis  = AnalysisTab(nb,  self)
        self.tab_structure = StructureTab(nb, self)
        self.tab_disasm    = DisasmTab(nb,    self)
        self.tab_apk       = APKAnalysisTab(nb, self)
        self.tab_anticheat = AntiCheatTab(nb, self)
        self.tab_medical   = MedicalTab(nb,   self)
        self.tab_report    = ReportTab(nb,    self)

        nb.add(self.tab_analysis,  text='🔬 Analysis')
        nb.add(self.tab_structure, text='📋 Structure')
        nb.add(self.tab_disasm,    text='⚙ Disasm / C')
        nb.add(self.tab_apk,       text='📦 APK Analysis')
        nb.add(self.tab_anticheat, text='🛡️ Anti-Cheat')
        nb.add(self.tab_medical,   text='🏥 Medical')
        nb.add(self.tab_report,    text='📝 Report')
        self._nb = nb

    def _build_statusbar(self):
        self._status = StatusBar(self._root)

    def _show_gpu_status(self):
        try:
            import cupy as cp
            cp.array([1])
            self._status.set_gpu("🟢 GPU: CuPy active")
        except Exception:
            self._status.set_gpu("🔴 GPU: NumPy fallback")

    # ── Queue / thread bridge ─────────────────────────────────────────────────

    def _poll_queue(self):
        while not self._q.empty():
            try:
                cmd, *args = self._q.get_nowait()
                if cmd == 'progress':
                    self.tab_analysis.update_progress(*args)
                elif cmd == 'status':
                    self._status.set(*args)
                elif cmd == 'scan_done':
                    self._on_scan_done(*args)
                elif cmd == 'parse_done':
                    self._on_parse_done(*args)
                elif cmd == 'decomp_done':
                    self._on_decomp_done(*args)
                elif cmd == 'malware_done':
                    self._on_malware_done(*args)
                elif cmd == 'apk_done':
                    self._on_apk_done(*args)
                elif cmd == 'anticheat_done':
                    self._on_anticheat_done(*args)
                elif cmd == 'error':
                    messagebox.showerror("Error", args[0])
                elif cmd == 'busy':
                    self._busy = args[0]
            except Exception as ex:
                print(f"[queue error] {ex}")
        self._root.after(80, self._poll_queue)

    def _put(self, *args):
        self._q.put(args)

    def _on_health_event_gui(self, event: HealthEvent):
        """Forward health events to medical tab (thread-safe via queue)."""
        # We call the method directly — Tkinter calls from callbacks are safe
        # only on the main thread; use after() for safety.
        self._root.after(0, self.tab_medical.on_health_event, event)

    # ── File operations ───────────────────────────────────────────────────────

    def open_file(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(
            title="Open binary file",
            filetypes=[
                ("Binary files", "*.so *.elf *.bin *.exe *.dll *.apk *.jar *.dex *.class *.zip"
                                 " *.gz *.zlib *.lz4 *.zst *.xz"),
                ("All files",    "*.*"),
            ])
        if not path:
            return

        self._current_file = path
        self.tab_analysis.update_path(path)
        self._status.set(f"Loading  {os.path.basename(path)}…")

        def _load():
            with open(path, 'rb') as f:
                data = f.read()
            self._current_data = data
            self._put('status', f"Loaded {len(data):,} bytes — ready")
            self._put('progress', 0.0, f"Loaded {os.path.basename(path)}")
            # Auto-parse
            self._put('status', "Parsing binary structure…")
            parse_res = parse_binary(data, medical_unit=self.medical_unit)
            self._parse_result = parse_res
            self._put('parse_done', parse_res)

        threading.Thread(target=_load, daemon=True).start()

    def _on_parse_done(self, parse_result):
        self.tab_analysis.clear_summary()
        self.tab_analysis.append_summary("  BINARY SUMMARY\n", 'header')
        self.tab_analysis.append_summary("  " + "─" * 50 + "\n", 'dim')
        self.tab_analysis.append_summary(section_summary(parse_result) + "\n", 'normal')
        self.tab_structure.populate(parse_result)
        self._status.set(
            f"Parsed: {parse_result.fmt.value}  "
            f"{parse_result.arch}  "
            f"{parse_result.bits}-bit  "
            f"{len(parse_result.sections)} sections")
        
        # Auto-analyze APK / JAR / ZIP containers
        if self._current_file and self._current_file.lower().endswith(('.apk', '.jar', '.zip')):
            self._status.set("Container detected, analyzing APK/jar structure…")
            self._analyze_apk_auto()

    # ── Scan ─────────────────────────────────────────────────────────────────

    def start_scan(self):
        if self._busy:
            return
        if not self._current_data:
            messagebox.showwarning("No file", "Open a binary file first.")
            return

        self._busy = True
        self.tab_analysis.clear_scan()
        self.tab_analysis.append_scan("  E-BOX 512 V3.2 — initiating scan…\n\n", 'header')
        self._status.set("Scanning…")

        win   = self.tab_analysis.window_size
        step  = self.tab_analysis.step_size

        def _scan():
            pipeline = EBox512(window_size=win, step_size=step)

            def _prog(pct, msg):
                self._put('progress', pct, msg)

            result = pipeline.scan(
                self._current_data,
                progress_cb=_prog,
                medical_unit=self.medical_unit)
            self._put('scan_done', result)
            self._put('busy', False)

        threading.Thread(target=_scan, daemon=True).start()

    def _on_scan_done(self, scan_result):
        self._scan_result = scan_result
        txt = self.tab_analysis

        # Register for cross-correlation
        self.medical_unit.register_scan(
            self._current_file or '', scan_result, self._parse_result)

        txt.append_scan(EBox512.summary_text(scan_result) + "\n", 'normal')

        if scan_result.confirmed:
            txt.append_scan("\n  🎯 CONFIRMED REGIONS:\n", 'confirmed')
            for v in scan_result.confirmed[:30]:
                txt.append_scan(f"    {v.reason}\n", 'confirmed')

        if scan_result.encrypted_regions:
            txt.append_scan("\n  🔐 ENCRYPTED REGIONS (top 15):\n", 'encrypted')
            for v in scan_result.encrypted_regions[:15]:
                txt.append_scan(
                    f"    0x{v.offset:08x}"
                    f"  H={v.metrics.H:.2f}"
                    f"  χ²={v.metrics.chi2_score:.2f}"
                    f"  R={v.metrics.R_norm:.2f}\n", 'encrypted')

        if scan_result.compressed_regions:
            txt.append_scan("\n  📦 COMPRESSED REGIONS (top 15):\n", 'compressed')
            for v in scan_result.compressed_regions[:15]:
                txt.append_scan(
                    f"    0x{v.offset:08x}"
                    f"  H={v.metrics.H:.2f}\n", 'compressed')

        # Encrypted ↔ section correlation
        if self._parse_result and scan_result.encrypted_regions:
            corrs = EBox512.correlate_encrypted_with_sections(
                scan_result, self._parse_result.sections)
            if corrs:
                txt.append_scan("\n  🔗 ENCRYPTED ↔ SECTION MAPPING:\n", 'header')
                for c in corrs[:15]:
                    txt.append_scan(
                        f"    0x{c['enc_offset']:08x} → {c['section']}"
                        f"  [{c['sec_range']}]"
                        f"  H={c['H']:.2f}\n", 'warn')

        # Start malware detector in background and stream progress
        txt.append_scan("\n  🦠 Running Malware Detector analysis…\n", 'header')

        def _run_malware():
            try:
                detector = MalwareDetector(window_size=self.tab_analysis.window_size,
                                           step_size=self.tab_analysis.step_size)

                def _mprog(pct, msg):
                    self._put('progress', pct, msg)

                # If an APK is loaded, analyze contained DEX and native libs
                apk_analyzer = None
                try:
                    apk_analyzer = global_apk_context.get_analyzer()
                except Exception:
                    apk_analyzer = None

                if apk_analyzer:
                    agg = MalwareScanResult()
                    conf_sums = {'malware': 0.0, 'rootkit': 0.0, 'aimbot': 0.0, 'anticheat': 0.0, 'virus': 0.0}
                    file_count = 0

                    # Analyze DEX files
                    try:
                        dex_files = apk_analyzer.extract_dex_files()
                    except Exception:
                        dex_files = []

                    for name, data in dex_files:
                        try:
                            # Parse member for structural info (strings/symbols)
                            try:
                                pr = parse_binary(data)
                            except Exception:
                                pr = None
                            res = detector.analyze_file(data, parse_result=pr, progress_cb=_mprog, medical_unit=self.medical_unit)
                        except Exception as ex:
                            agg.errors.append(str(ex))
                            continue
                        file_count += 1
                        agg.total_scanned += getattr(res, 'total_scanned', 0)
                        agg.malware.extend(res.malware)
                        agg.rootkit.extend(res.rootkit)
                        agg.aimbot.extend(res.aimbot)
                        agg.anticheat.extend(res.anticheat)
                        if hasattr(res, 'virus'):
                            agg.virus.extend(res.virus)
                        agg.clean += getattr(res, 'clean', 0)
                        agg.errors.extend(getattr(res, 'errors', []))
                        for k in conf_sums.keys():
                            conf_sums[k] += res.overall_confidences.get(k, 0.0)

                    # Analyze native libraries (if any)
                    try:
                        native_list = list(apk_analyzer.metadata.native_libs)
                    except Exception:
                        native_list = []

                    for entry in native_list:
                        member = f"lib/{entry}"
                        try:
                            data = apk_analyzer.zip_file.read(member)
                        except Exception:
                            continue
                        try:
                            try:
                                pr = parse_binary(data)
                            except Exception:
                                pr = None
                            res = detector.analyze_file(data, parse_result=pr, progress_cb=_mprog, medical_unit=self.medical_unit)
                        except Exception as ex:
                            agg.errors.append(str(ex))
                            continue
                        file_count += 1
                        agg.total_scanned += getattr(res, 'total_scanned', 0)
                        agg.malware.extend(res.malware)
                        agg.rootkit.extend(res.rootkit)
                        agg.aimbot.extend(res.aimbot)
                        agg.anticheat.extend(res.anticheat)
                        if hasattr(res, 'virus'):
                            agg.virus.extend(res.virus)
                        agg.clean += getattr(res, 'clean', 0)
                        agg.errors.extend(getattr(res, 'errors', []))
                        for k in conf_sums.keys():
                            conf_sums[k] += res.overall_confidences.get(k, 0.0)

                    if file_count == 0:
                        # Fallback to analyzing the opened binary
                        mres = detector.analyze_file(self._current_data, parse_result=self._parse_result, progress_cb=_mprog, medical_unit=self.medical_unit)
                    else:
                        # Average confidences across files
                        agg.overall_confidences = {k: (conf_sums[k] / max(1, file_count)) for k in conf_sums}
                        mres = agg
                else:
                    mres = detector.analyze_file(
                        self._current_data,
                        parse_result=self._parse_result,
                        progress_cb=_mprog,
                        medical_unit=self.medical_unit)

                self._put('malware_done', mres)
            except Exception as e:
                self._put('error', f"Malware analysis failed: {e}")

        threading.Thread(target=_run_malware, daemon=True).start()

        self._status.set(
            f"Scan complete — "
            f"{len(scan_result.confirmed)} confirmed  "
            f"{len(scan_result.encrypted_regions)} encrypted  "
            f"T={scan_result.threshold_T:.3f}")

    def _on_malware_done(self, mres):
        """Handle MalwareDetector results and display summaries in Analysis tab."""
        self._malware_result = mres
        txt = self.tab_analysis

        try:
            txt.append_scan("\n" + MalwareDetector.summary_text(mres) + "\n", 'normal')
        except Exception:
            txt.append_scan("\n  Malware analysis complete.\n", 'normal')

        # Show overall confidences per category
        if getattr(mres, 'overall_confidences', None):
            lines = ["\n  OVERALL CONFIDENCES (per-category):"]
            for k, v in mres.overall_confidences.items():
                lines.append(f"    {k.upper():<10}: {v*100:.1f}%")
            txt.append_scan("\n".join(lines) + "\n", 'header')

        # Helper to show top detections with operational probability
        def show_list(lst, label):
            if not lst:
                return
            txt.append_scan(f"\n  {label} (top 10):\n", 'confirmed')
            for d in lst[:10]:
                txt.append_scan(
                    f"    0x{d.offset:08x}  Conf={d.confidence:.2f}  OpProb={d.operational_prob:.2f}  {d.reason}\n",
                    'normal')

        show_list(mres.malware, 'MALWARE')
        show_list(mres.rootkit, 'ROOTKIT')
        show_list(mres.aimbot, 'AIMBOT')
        show_list(mres.anticheat, 'ANTICHEAT')
        if hasattr(mres, 'virus'):
            show_list(mres.virus, 'VIRUS')

        self._status.set("Malware analysis complete")
        self._put('progress', 100.0, "Malware analysis complete")

    def start_malware_analysis(self):
        """Manual trigger for malware detection (independent of EBox512)."""
        if self._busy:
            return
        if not self._current_data:
            messagebox.showwarning("No file", "Open a binary file first.")
            return

        self._busy = True
        self.tab_analysis.clear_scan()
        self.tab_analysis.append_scan("  🦠 Malware Detector — running…\n\n", 'header')
        self._status.set("Running malware analysis…")

        def _run_malware():
            try:
                detector = MalwareDetector(window_size=self.tab_analysis.window_size,
                                           step_size=self.tab_analysis.step_size)

                def _mprog(pct, msg):
                    self._put('progress', pct, msg)

                mres = detector.analyze_file(
                    self._current_data,
                    parse_result=self._parse_result,
                    progress_cb=_mprog,
                    medical_unit=self.medical_unit)
                self._put('malware_done', mres)
            except Exception as e:
                self._put('error', f"Malware analysis failed: {e}")
            finally:
                self._put('busy', False)

        threading.Thread(target=_run_malware, daemon=True).start()

    # ── Decompile ─────────────────────────────────────────────────────────────

    def start_decompile(self):
        if self._busy:
            return
        if not self._current_data:
            messagebox.showwarning("No file", "Open a binary file first.")
            return

        self._busy = True
        self._nb.select(self.tab_disasm)
        self.tab_disasm._asm_txt.clear()
        self.tab_disasm._c_txt.clear()
        self.tab_disasm._asm_txt.append("  Disassembling…\n", 'dim')
        self._status.set("Disassembling…")

        arch = self.tab_disasm.arch
        start_offset = self.tab_disasm.start_offset
        end_offset = self.tab_disasm.end_offset
        self._last_start_offset = start_offset
        self._last_end_offset = end_offset

        def _decomp():
            result = decompile(
                self._current_data,
                arch=arch,
                start_offset=start_offset,
                end_offset=end_offset,
                medical_unit=self.medical_unit)
            self._put('decomp_done', result)
            self._put('busy', False)

        threading.Thread(target=_decomp, daemon=True).start()

    def _on_decomp_done(self, decomp_result):
        self._decomp_result = decomp_result
        self.tab_disasm.populate(decomp_result)
        offset_info = ""
        if hasattr(self, '_last_start_offset') and hasattr(self, '_last_end_offset') and \
           self._last_start_offset is not None and self._last_end_offset is not None:
            offset_info = f" (0x{self._last_start_offset:08x}-0x{self._last_end_offset:08x})"
        self._status.set(
            f"Decompiled{offset_info} — "
            f"{len(decomp_result.instructions)} instructions  "
            f"{len(decomp_result.functions)} functions  "
            f"{len(decomp_result.strings)} strings")

    # ── APK Analysis ────────────────────────────────────────────────────────────

    def _analyze_apk_auto(self):
        """Automatically analyze APK from loaded binary data."""
        if not self._current_data:
            return
        
        self._busy = True
        self._nb.select(self.tab_apk)

        def _analyse_apk():
            try:
                from apk_analyzer import analyze_apk_from_bytes
                success, summary, analyzer = analyze_apk_from_bytes(self._current_data)
                if success:
                    analytics = analyzer.analyze_compression_structure()
                    self._put('apk_done', {
                        'success': True,
                        'analyzer': analyzer,
                        'files': analyzer.files,
                        'metadata': analyzer.metadata,
                        'analysis': analytics,
                        'summary': summary
                    })
                else:
                    self._put('error', f"APK Analysis failed: {summary}")
            except Exception as e:
                self._put('error', f"APK error: {e}")
            finally:
                self._put('busy', False)

        threading.Thread(target=_analyse_apk, daemon=True).start()

    def _open_apk_file(self, path: str):
        """[DEPRECATED] Open APK file - now use Analysis tab instead."""
        messagebox.showinfo("APK Analysis", 
                           "Please use the 🔬 Analysis tab to open APK files.\n"
                           "APK analysis will start automatically when you open a .apk file.")

    def _analyze_apk(self):
        """[DEPRECATED] Analyze APK - now use auto-analysis."""
        messagebox.showinfo("APK Analysis", 
                           "Please use the 🔬 Analysis tab to open APK files.\n"
                           "APK analysis will start automatically when you open a .apk file.")

    def _on_apk_done(self, apk_result):
        """Handle APK analysis completion."""
        if not apk_result.get('success'):
            self._status.set("APK analysis failed")
            return
        analyzer = apk_result['analyzer']
        # Keep reference to analyzer so we can extract/decompress later
        try:
            # Close previous analyzer if present
            if getattr(self, '_apk_analyzer', None):
                try:
                    self._apk_analyzer.close()
                except Exception:
                    pass
        except Exception:
            pass
        self._apk_analyzer = analyzer
        try:
            global_apk_context.set_analyzer(analyzer)
        except Exception:
            pass
        self.tab_apk.populate_structure(apk_result['files'])
        self.tab_apk.show_metadata(apk_result['metadata'])
        self.tab_apk.show_compression_analysis(apk_result['analysis'])
        self.tab_apk.show_summary(apk_result['summary'])
        
        # Update APK tab filename from current file
        if self._current_file:
            self.tab_apk._apk_path_var.set(os.path.basename(self._current_file))

        self._status.set(f"APK analyzed: {len(apk_result['files'])} files, "
                        f"{apk_result['metadata'].total_size:,} bytes")

    def _apk_cleanup(self):
        """Cleanup APK analyzer and associated extract dir."""
        try:
            if getattr(self, '_apk_analyzer', None):
                try:
                    self._apk_analyzer.close()
                except Exception:
                    pass
            self._apk_analyzer = None
        finally:
            self._apk_extract_dir = None
        try:
            global_apk_context.clear()
        except Exception:
            pass

    def _apk_extract_all(self):
        """Extract all APK files to a temporary directory."""
        if not getattr(self, '_apk_analyzer', None):
            messagebox.showwarning("No APK", "Open APK via Analysis tab first.")
            return
        written, outdir = global_apk_context.extract_all()
        if written:
            self._apk_extract_dir = outdir
            messagebox.showinfo("Extracted", f"Extracted {len(written)} files to:\n{outdir}")
        else:
            messagebox.showerror("Error", "Extraction failed or no files written.")

    def _apk_extract_selected(self):
        """Extract selected file in APK tree to extract dir."""
        if not getattr(self, '_apk_analyzer', None):
            messagebox.showwarning("No APK", "Open APK via Analysis tab first.")
            return
        sel = self.tab_apk._tree.selection()
        if not sel:
            messagebox.showwarning("Select file", "Select a file in the APK tree first.")
            return
        member = sel[0]
        ok, dest = global_apk_context.extract_member(member)
        if ok:
            self._apk_extract_dir = os.path.dirname(dest)
            messagebox.showinfo("Extracted", f"Extracted {member} to {dest}")
        else:
            messagebox.showerror("Error", f"Failed to extract {member}")

    def _apk_decompress_selected(self):
        """Attempt to decompress selected file and write result."""
        if not getattr(self, '_apk_analyzer', None):
            messagebox.showwarning("No APK", "Open APK via Analysis tab first.")
            return
        sel = self.tab_apk._tree.selection()
        if not sel:
            messagebox.showwarning("Select file", "Select a file in the APK tree first.")
            return
        member = sel[0]
        ok, dest = global_apk_context.decompress_member(member)
        if ok:
            self._apk_extract_dir = os.path.dirname(dest)
            messagebox.showinfo("Decompressed", f"Decompressed to {dest}")
        else:
            messagebox.showwarning("No decompression", "File did not appear to be compressed or decompression failed.")

    def _apk_decompile_selected(self):
        """Decompile the selected APK file entry (if it contains executable code)."""
        if not getattr(self, '_apk_analyzer', None):
            messagebox.showwarning("No APK", "Open APK via Analysis tab first.")
            return
        sel = self.tab_apk._tree.selection()
        if not sel:
            messagebox.showwarning("Select file", "Select a file in the APK tree first.")
            return
        member = sel[0]
        try:
            analyzer = global_apk_context.get_analyzer()
            data = analyzer.zip_file.read(member)
        except Exception as e:
            messagebox.showerror("Read failed", f"Failed to read {member}: {e}")
            return

        # Use existing decompile flow but operate on the member bytes
        self._busy = True
        self._nb.select(self.tab_disasm)
        self.tab_disasm._asm_txt.clear()
        self.tab_disasm._c_txt.clear()
        self.tab_disasm._asm_txt.append(f"  Disassembling {member}…\n", 'dim')
        self._status.set(f"Disassembling {member}…")

        def _do():
            try:
                result = decompile(data, arch=None, medical_unit=self.medical_unit)
                self._put('decomp_done', result)
            except Exception as ex:
                self._put('error', f"Decompile failed: {ex}")
            finally:
                self._put('busy', False)

        threading.Thread(target=_do, daemon=True).start()

    def _apk_open_extract_dir(self):
        """Open the extract directory in the OS file manager."""
        if not getattr(self, '_apk_extract_dir', None):
            messagebox.showwarning("No extracts", "No extract directory available.")
            return
        try:
            if sys.platform.startswith('win'):
                os.startfile(self._apk_extract_dir)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', self._apk_extract_dir])
            else:
                subprocess.Popen(['xdg-open', self._apk_extract_dir])
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def on_apk_member_selected(self, member: str):
        """Called when user selects a file in the APK tree — parse and show structure."""
        try:
            analyzer = global_apk_context.get_analyzer()
        except Exception:
            analyzer = None
        if not analyzer:
            messagebox.showwarning("No APK", "Open APK via Analysis tab first.")
            return

        self._status.set(f"Parsing APK member: {member}")

        try:
            data = analyzer.zip_file.read(member)
        except Exception as e:
            messagebox.showerror("Read failed", f"Failed to read {member}: {e}")
            return

        # Parse the selected member and populate the Structure tab
        try:
            pr = parse_binary(data)
        except Exception as e:
            pr = None
            messagebox.showwarning("Parse failed", f"Parsing {member} failed: {e}")

        if pr:
            # Keep parse result per-member for possible further actions
            try:
                if not hasattr(self, '_apk_member_parses') or self._apk_member_parses is None:
                    self._apk_member_parses = {}
                self._apk_member_parses[member] = pr
            except Exception:
                pass

            # Show Structure tab with this parse
            try:
                self._nb.select(self.tab_structure)
                self.tab_structure.populate(pr)
                self._status.set(f"Showing structure for {member}")
            except Exception:
                pass

    # ── Anti-Cheat Analysis ─────────────────────────────────────────────────────

    def _analyze_anticheat(self):
        """Analyze binary for anti-cheat and protection mechanisms."""
        if not self._current_data:
            messagebox.showwarning("No file", "Open a binary file first.")
            return

        self._busy = True
        self._nb.select(self.tab_anticheat)
        self._status.set("Analyzing anti-cheat mechanisms…")

        def _analyze_ac():
            try:
                detector = AntiCheatDetector()
                # If an APK is loaded, analyze APK contents
                try:
                    apk_an = global_apk_context.get_analyzer()
                except Exception:
                    apk_an = None

                if apk_an:
                    apk_files = {}
                    try:
                        for member in apk_an.zip_file.namelist():
                            try:
                                apk_files[member] = apk_an.zip_file.read(member)
                            except Exception:
                                continue
                    except Exception:
                        apk_files = {}
                    analysis = detector.analyze_apk(apk_files)
                else:
                    analysis = detector.analyze_binary(self._current_data)
                self._put('anticheat_done', analysis)
            except Exception as e:
                self._put('error', f"Anti-cheat analysis failed: {e}")
            finally:
                self._put('busy', False)

        threading.Thread(target=_analyze_ac, daemon=True).start()

    def _on_anticheat_done(self, analysis):
        """Handle anti-cheat analysis completion."""
        self.tab_anticheat.populate_findings(analysis.findings)
        self.tab_anticheat.show_risk_assessment(analysis)

        risk_name = analysis.overall_risk.name
        finding_count = len(analysis.findings)
        self._status.set(f"Anti-cheat analysis: {risk_name} risk, "
                        f"{finding_count} findings")

    # ── Run ──────────────────────────────────────────────────────────────────

    def run(self):
        self._root.mainloop()


# ─────────────────────────────────────────────────────────────────────────────

def main():
    app = REToolApp()
    app.run()


if __name__ == '__main__':
    main()
