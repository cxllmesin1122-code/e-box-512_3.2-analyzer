"""
Anti-Cheat Analysis Tab — Display anti-cheat detection results
"""

import tkinter as tk
from tkinter import ttk, scrolledtext

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


class AntiCheatTab(tk.Frame):
    """Tab for anti-cheat and protection mechanism detection."""
    
    def __init__(self, master, app=None, **kw):
        super().__init__(master, bg=C_BG, **kw)
        self.app = app
        self._build()
    
    def _build(self):
        """Build the anti-cheat tab UI."""
        
        # ── Top controls ────────────────────────────────────
        top = tk.Frame(self, bg=C_BG2, pady=6, padx=8)
        top.pack(fill='x', side='top')
        
        tk.Label(top, text="🛡️ Anti-Cheat & Protection Analysis",
                bg=C_BG2, fg=C_CYAN, font=_mono(11, 'bold'),
                anchor='w').pack(side='left')
        
        btn_kw = dict(bg=C_BG3, fg=C_FG, relief='flat',
                     activebackground=C_CYAN, activeforeground=C_BG,
                     font=_mono(9), padx=10, pady=3, cursor='hand2')
        tk.Button(top, text="Analyze", 
                 command=self._analyze, **btn_kw).pack(side='right', padx=2)
        tk.Button(top, text="Clear",    
                 command=self._clear, **btn_kw).pack(side='right', padx=2)
        
        # ── Main layout ─────────────────────────────────────
        pane = tk.PanedWindow(self, orient='horizontal',
                             bg=C_BG, sashwidth=4, sashrelief='flat')
        pane.pack(fill='both', expand=True, padx=4, pady=4)
        
        # ── Left: Detection list ────────────────────────────
        left = tk.Frame(pane, bg=C_BG2)
        tk.Label(left, text="🔍 Detections",
                bg=C_BG2, fg=C_CYAN, font=_mono(11, 'bold'),
                anchor='w').pack(fill='x', padx=4, pady=4)
        
        # Listbox for detections
        list_frame = tk.Frame(left, bg=C_BG2)
        list_frame.pack(fill='both', expand=True)
        
        sb = tk.Scrollbar(list_frame, orient='vertical',
                         bg=C_BG3, troughcolor=C_BG2, bd=0)
        self._findings_list = tk.Listbox(
            list_frame, bg=C_BG3, fg=C_FG,
            font=_mono(9), relief='flat', bd=0,
            yscrollcommand=sb.set)
        sb.config(command=self._findings_list.yview)
        
        sb.pack(side='right', fill='y')
        self._findings_list.pack(fill='both', expand=True)
        self._findings_list.bind('<<ListboxSelect>>', self._on_finding_select)
        
        pane.add(left, minsize=300)
        
        # ── Right: Risk assessment ──────────────────────────
        right = tk.Frame(pane, bg=C_BG2)
        
        # Summary panel
        summary_frame = tk.Frame(right, bg=C_BG2, height=100)
        summary_frame.pack(fill='x', padx=4, pady=4)
        summary_frame.pack_propagate(False)
        
        tk.Label(summary_frame, text="📊 Overall Assessment",
                bg=C_BG2, fg=C_CYAN, font=_mono(10, 'bold'),
                anchor='w').pack(fill='x', padx=4, pady=2)
        
        # Risk indicators
        risk_frame = tk.Frame(summary_frame, bg=C_BG3)
        risk_frame.pack(fill='x', padx=4, pady=4)
        
        self._risk_var = tk.StringVar(value="UNKNOWN")
        tk.Label(risk_frame, textvariable=self._risk_var,
                bg=C_BG3, fg=C_FG, font=_mono(12, 'bold'),
                anchor='w').pack(side='left', padx=8, pady=4)
        
        # Obfuscation score
        obf_frame = tk.Frame(summary_frame, bg=C_BG3)
        obf_frame.pack(fill='x', padx=4, pady=4)
        
        tk.Label(obf_frame, text="Obfuscation Score:",
                bg=C_BG3, fg=C_FG2, font=_mono(9)).pack(side='left', padx=4)
        self._obf_var = tk.StringVar(value="0%")
        tk.Label(obf_frame, textvariable=self._obf_var,
                bg=C_BG3, fg=C_YELLOW, font=_mono(10, 'bold')).pack(side='left', padx=4)
        
        # Detected mechanisms
        details_frame = tk.Frame(right, bg=C_BG2)
        details_frame.pack(fill='both', expand=True, padx=4, pady=4)
        
        tk.Label(details_frame, text="📝 Details",
                bg=C_BG2, fg=C_CYAN, font=_mono(10, 'bold'),
                anchor='w').pack(fill='x', padx=4, pady=2)
        
        self._detail_text = scrolledtext.ScrolledText(
            details_frame, bg=C_BG3, fg=C_FG, font=_mono(),
            wrap='word', state='disabled', height=20)
        self._detail_text.pack(fill='both', expand=True)
        
        pane.add(right, minsize=350)
    
    def populate_findings(self, findings_list):
        """Populate findings listbox."""
        self._findings_list.delete(0, 'end')
        
        for i, finding in enumerate(findings_list):
            display = f"[{finding.risk_level.name}] {finding.name}"
            self._findings_list.insert('end', display)
            
            # Color by risk level
            risk_colors = {
                'CRITICAL': C_RED,
                'HIGH': C_ORANGE,
                'MEDIUM': C_YELLOW,
                'LOW': C_CYAN,
                'NONE': C_GREEN,
            }
            
            color = risk_colors.get(finding.risk_level.name, C_FG2)
            self._findings_list.itemconfig(i, {'fg': color})
    
    def show_risk_assessment(self, analysis):
        """Display overall risk assessment."""
        risk_colors = {
            'CRITICAL': C_RED,
            'HIGH': C_ORANGE,
            'MEDIUM': C_YELLOW,
            'LOW': C_CYAN,
            'NONE': C_GREEN,
        }
        
        risk_name = analysis.overall_risk.name
        color = risk_colors.get(risk_name, C_FG)
        
        self._risk_var.set(f"⚠️ Risk Level: {risk_name}")
        
        obf_pct = analysis.obfuscation_score * 100
        self._obf_var.set(f"{obf_pct:.0f}%")
        
        # Build detail text
        lines = [f"Analysis Report",
                f"{'='*50}",
                f"\nOverall Risk: {risk_name}",
                f"Total Findings: {len(analysis.findings)}",
                f"Obfuscation Score: {obf_pct:.1f}%",
                f"\nDetected Mechanisms:"]
        
        if analysis.anti_debug_detected:
            lines.append(f"  ✓ Anti-Debugging")
        if analysis.anti_tamper_detected:
            lines.append(f"  ✓ Anti-Tampering")
        if analysis.drm_detected:
            lines.append(f"  ✓ DRM/License Verification")
        
        if not (analysis.anti_debug_detected or analysis.anti_tamper_detected 
                or analysis.drm_detected):
            lines.append(f"  • None detected")
        
        lines.append(f"\nDetailed Findings:")
        for finding in analysis.findings:
            lines.append(f"\n  [{finding.risk_level.name:8}] {finding.name}")
            lines.append(f"     {finding.description}")
            if finding.confidence > 0:
                lines.append(f"     Confidence: {finding.confidence:.0%}")
        
        self._update_detail_text("\n".join(lines))
    
    def show_finding_details(self, finding):
        """Display specific finding details."""
        lines = [
            f"Finding: {finding.name}",
            f"{'='*50}",
            f"Type: {finding.type.value}",
            f"Risk Level: {finding.risk_level.name}",
            f"Confidence: {finding.confidence:.0%}",
            f"\nDescription:",
            f"{finding.description}",
            f"\nLocation: {finding.location if finding.location else 'N/A'}",
        ]
        
        self._update_detail_text("\n".join(lines))
    
    def _on_finding_select(self, event):
        """Handle finding selection."""
        selection = self._findings_list.curselection()
        if selection and self.app:
            idx = selection[0]
            # Note: Would need to pass findings from app
            pass
    
    def _analyze(self):
        """Start anti-cheat analysis."""
        if self.app:
            self.app._analyze_anticheat()
    
    def _clear(self):
        """Clear display."""
        self._findings_list.delete(0, 'end')
        self._risk_var.set("UNKNOWN")
        self._obf_var.set("0%")
        self._update_detail_text("")
    
    def _update_detail_text(self, text: str):
        """Update detail text display."""
        self._detail_text.config(state='normal')
        self._detail_text.delete('1.0', 'end')
        self._detail_text.insert('1.0', text)
        self._detail_text.config(state='disabled')
    
    def append_finding(self, text: str):
        """Append finding to list."""
        self._findings_list.insert('end', text)
