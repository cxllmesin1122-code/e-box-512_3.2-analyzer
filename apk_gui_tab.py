"""
APK Analysis Tab — Display APK structure, compression analysis, and findings
"""

import tkinter as tk
from tkinter import ttk
import os


# Theme colors
C_BG = "#0d1117"
C_BG2 = "#161b22"
C_BG3 = "#1f2937"
C_FG = "#e6edf3"
C_FG2 = "#8b949e"
C_CYAN = "#58a6ff"
C_GREEN = "#3fb950"
C_ORANGE = "#f0883e"
C_RED = "#f85149"
C_YELLOW = "#e3b341"
C_MONO = "Consolas"


def _mono(size: int = 10, style: str = '') -> tuple:
    if style:
        return (C_MONO, size, style)
    return (C_MONO, size)


class APKAnalysisTab(tk.Frame):
    """Tab for APK analysis — structure, compression, permissions."""
    
    def __init__(self, master, app=None, **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self.current_apk = None
        self.tree_items = {}
        self._build()
    
    def _build(self):
        """Build the APK tab UI."""
        
        # ── Top controls ────────────────────────────────────
        top = tk.Frame(self, bg=C_BG2, pady=6, padx=8)
        top.pack(fill='x', side='top')
        
        tk.Label(top, text="📦 APK File (from 🔬 Analysis tab):",
                bg=C_BG2, fg=C_FG2, font=_mono(9)).pack(side='left')
        self._apk_path_var = tk.StringVar(value="<open APK in Analysis tab>")
        tk.Label(top, textvariable=self._apk_path_var,
                bg=C_BG2, fg=C_CYAN, font=_mono(9),
                width=50, anchor='w').pack(side='left', padx=6)
        
        btn_kw = dict(bg=C_BG3, fg=C_FG, relief='flat',
                 activebackground=C_CYAN, activeforeground=C_BG,
                 font=_mono(9), padx=10, pady=3, cursor='hand2')
        # Extraction utilities (use Analysis tab to open APK first)
        tk.Button(top, text="Extract All", command=lambda: self.app._apk_extract_all(), **btn_kw).pack(side='right', padx=2)
        tk.Button(top, text="Extract Sel", command=lambda: self.app._apk_extract_selected(), **btn_kw).pack(side='right', padx=2)
        tk.Button(top, text="Decompress Sel", command=lambda: self.app._apk_decompress_selected(), **btn_kw).pack(side='right', padx=2)
        tk.Button(top, text="Decompile Sel", command=lambda: self.app._apk_decompile_selected(), **btn_kw).pack(side='right', padx=2)
        tk.Button(top, text="Open Folder", command=lambda: self.app._apk_open_extract_dir(), **btn_kw).pack(side='right', padx=2)
        tk.Button(top, text="Clear",    
             command=self._clear, **btn_kw).pack(side='right', padx=2)
        
        # ── Paned layout ────────────────────────────────────
        pane = tk.PanedWindow(self, orient='horizontal',
                             bg=C_BG, sashwidth=4, sashrelief='flat')
        pane.pack(fill='both', expand=True, padx=4, pady=4)
        
        # ── Left: File tree ─────────────────────────────────
        left = tk.Frame(pane, bg=C_BG2)
        tk.Label(left, text="📂 APK Structure",
                bg=C_BG2, fg=C_CYAN, font=_mono(11, 'bold'),
                anchor='w').pack(fill='x', padx=4, pady=4)
        
        # Treeview for files
        tree_frame = tk.Frame(left, bg=C_BG2)
        tree_frame.pack(fill='both', expand=True)
        
        cols = ('name', 'size', 'compressed', 'entropy', 'type')
        self._tree = ttk.Treeview(tree_frame, columns=cols, show='headings',
                                 selectmode='browse', height=25)
        
        for col, width, label in zip(
                cols, [200, 80, 80, 60, 80],
                ['File/Folder', 'Size', 'Compressed', 'Entropy', 'Type']):
            self._tree.heading(col, text=label)
            self._tree.column(col, width=width, anchor='w')
        
        sb = tk.Scrollbar(tree_frame, orient='vertical', command=self._tree.yview,
                         bg=C_BG3, troughcolor=C_BG2, bd=0)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)
        # Bind selection to notify app (so Structure tab can show strings/symbols)
        self._tree.bind('<<TreeviewSelect>>', self._on_tree_select)

        pane.add(left, minsize=350)
        
        # ── Right: Analysis panels ──────────────────────────
        right = tk.Frame(pane, bg=C_BG2)
        
        # Notebook for different views
        self._right_notebook = ttk.Notebook(right)
        self._right_notebook.pack(fill='both', expand=True, padx=4, pady=4)
        
        # Tab 1: Metadata
        meta_frame = tk.Frame(self._right_notebook, bg=C_BG3)
        self._right_notebook.add(meta_frame, text='📋 Metadata')
        
        from tkinter import scrolledtext
        self._meta_text = scrolledtext.ScrolledText(
            meta_frame, bg=C_BG3, fg=C_FG, font=_mono(),
            wrap='word', state='disabled')
        self._meta_text.pack(fill='both', expand=True)
        
        # Tab 2: Compression Analysis
        comp_frame = tk.Frame(self._right_notebook, bg=C_BG3)
        self._right_notebook.add(comp_frame, text='📊 Compression')
        
        self._comp_text = scrolledtext.ScrolledText(
            comp_frame, bg=C_BG3, fg=C_FG, font=_mono(),
            wrap='word', state='disabled')
        self._comp_text.pack(fill='both', expand=True)
        
        # Tab 3: Files Summary
        files_frame = tk.Frame(self._right_notebook, bg=C_BG3)
        self._right_notebook.add(files_frame, text='📁 Summary')
        
        self._files_text = scrolledtext.ScrolledText(
            files_frame, bg=C_BG3, fg=C_FG, font=_mono(),
            wrap='word', state='disabled')
        self._files_text.pack(fill='both', expand=True)
        
        pane.add(right, minsize=400)
    
    def _clear(self):
        """Clear all display."""
        self._tree.delete(*self._tree.get_children())
        self._update_text(self._meta_text, "")
        self._update_text(self._comp_text, "")
        self._update_text(self._files_text, "")
        self._apk_path_var.set("<open APK in Analysis tab>")
        self.current_apk = None
        # Ask app to cleanup analyzer state
        try:
            if hasattr(self, 'app') and self.app:
                self.app._apk_cleanup()
        except Exception:
            pass
    
    def populate_structure(self, files: list):
        """Populate file tree with APK structure."""
        self._tree.delete(*self._tree.get_children())
        self.tree_items.clear()
        
        for file_info in files:
            parts = file_info.path.split('/')
            
            # Insert into tree
            parent = ""
            for i, part in enumerate(parts[:-1]):
                parent_key = '/'.join(parts[:i+1])
                if parent_key not in self.tree_items:
                    parent_id = self._tree.insert(parent, 'end', parent_key,
                                                 text=part, open=False)
                    self.tree_items[parent_key] = parent_id
                parent = parent_key
            
            # Add file
            file_key = file_info.path
            if parent:
                parent_id = self.tree_items.get(parent, "")
            else:
                parent_id = ""
            
            size_kb = f"{file_info.size / 1024:.1f}K"
            comp_kb = f"{file_info.compressed_size / 1024:.1f}K"
            entropy_str = f"{file_info.entropy:.2f}"
            file_type = file_info.file_type.name if file_info.file_type else "FILE"
            
            self._tree.insert(parent_id, 'end', file_key,
                            values=(parts[-1], size_kb, comp_kb, entropy_str, file_type))
    
    def show_metadata(self, metadata):
        """Display APK metadata."""
        lines = [
            f"Package: {metadata.package_name}",
            f"Version: {metadata.version_name} (code: {metadata.version_code})",
            f"API Level: {metadata.min_api_level} → {metadata.target_api_level}",
            f"Label: {metadata.app_label}",
            f"\nNative Libraries ({len(metadata.native_libs)}): ",
        ]
        
        for lib in metadata.native_libs[:20]:
            lines.append(f"  • {lib}")
        
        if len(metadata.native_libs) > 20:
            lines.append(f"  ... and {len(metadata.native_libs) - 20} more")
        
        lines.append(f"\nDEX Files ({len(metadata.dex_files)}):")
        for dex in metadata.dex_files:
            lines.append(f"  • {dex}")
        
        lines.append(f"\nPermissions ({len(metadata.permissions)}):")
        for perm in metadata.permissions[:15]:
            lines.append(f"  • {perm}")
        
        if len(metadata.permissions) > 15:
            lines.append(f"  ... and {len(metadata.permissions) - 15} more")
        
        self._update_text(self._meta_text, "\n".join(lines))
    
    def show_compression_analysis(self, analysis: dict):
        """Display compression analysis."""
        lines = [
            f"Total Files: {analysis.get('total_files', 0)}",
            f"Uncompressed: {analysis.get('uncompressed_size', 0):,} bytes",
            f"Compressed: {analysis.get('compressed_size', 0):,} bytes",
            f"Ratio: {analysis.get('compression_ratio', 0):.2%}",
            f"Average Entropy: {analysis.get('avg_entropy', 0):.2f}",
            f"\nFiles by Type:",
        ]
        
        for file_type, stats in analysis.get('files_by_type', {}).items():
            lines.append(f"  {file_type}: {stats['count']} files "
                        f"({stats['size']:,} bytes)")
        
        lines.append(f"\nHigh Entropy Files (Encrypted/Compressed):")
        for f in analysis.get('high_entropy_files', []):
            lines.append(f"  • {f.path} (H: {f.entropy:.2f})")
        
        lines.append(f"\nLow Compression Ratio (Already Compressed):")
        for f in analysis.get('low_compression_files', []):
            lines.append(f"  • {f.path} ({f.compression_ratio:.1%})")
        
        self._update_text(self._comp_text, "\n".join(lines))
    
    def show_summary(self, summary: str):
        """Display summary."""
        self._update_text(self._files_text, summary)

    def _on_tree_select(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        member = sel[0]
        try:
            if hasattr(self, 'app') and self.app:
                # Delegate handling to the main app
                try:
                    self.app.on_apk_member_selected(member)
                except Exception:
                    pass
        except Exception:
            pass
    
    def append_metadata(self, text: str):
        """Append to metadata display."""
        self._meta_text.config(state='normal')
        self._meta_text.insert('end', text + '\n')
        self._meta_text.config(state='disabled')
        self._meta_text.see('end')
    
    def _update_text(self, text_widget, content: str):
        """Update text widget content."""
        text_widget.config(state='normal')
        text_widget.delete('1.0', 'end')
        text_widget.insert('1.0', content)
        text_widget.config(state='disabled')
