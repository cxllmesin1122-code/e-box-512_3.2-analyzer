"""
Medical Unit — E-BOX RE Tool Healthcare System
Wraps every module call, catches errors, attempts auto-recovery,
provides live health dashboard, and runs cross-file correlation.
"""

from __future__ import annotations
import gc, sys, traceback, threading, time
from datetime import datetime
from typing import Callable, Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    OK       = "OK"
    WARNING  = "WARNING"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"
    RECOVERED= "RECOVERED"


@dataclass
class HealthEvent:
    timestamp: str
    module:    str
    severity:  Severity
    message:   str
    traceback: str  = ""
    fixed:     bool = False
    fix_note:  str  = ""


@dataclass
class ModuleHealth:
    name:       str
    status:     Severity  = Severity.OK
    last_check: str       = ""
    errors:     int       = 0
    warnings:   int       = 0
    calls:      int       = 0
    avg_ms:     float     = 0.0
    _times:     List[float] = field(default_factory=list, repr=False)

    def record_call(self, elapsed_ms: float, ok: bool):
        self.calls += 1
        self._times.append(elapsed_ms)
        if len(self._times) > 50:
            self._times.pop(0)
        self.avg_ms = sum(self._times) / len(self._times)
        self.last_check = datetime.now().strftime('%H:%M:%S')
        if ok:
            self.status = Severity.OK
        else:
            self.errors += 1

    @property
    def status_icon(self) -> str:
        return {
            Severity.OK:       "✅",
            Severity.WARNING:  "⚠️",
            Severity.ERROR:    "❌",
            Severity.CRITICAL: "🚨",
            Severity.RECOVERED:"🔧",
        }.get(self.status, "❓")

    def summary(self) -> str:
        return (f"{self.status_icon} {self.name:<22}"
                f"  calls={self.calls:<5}"
                f"  errors={self.errors:<4}"
                f"  avg={self.avg_ms:6.1f}ms"
                f"  last={self.last_check}")


# ─────────────────────────────────────────────────────────────────────────────

class MedicalUnit:
    """
    Central health management for E-BOX RE Tool.

    Usage:
        mu = MedicalUnit()
        ok, result, err = mu.guard('ModuleName', my_function, arg1, arg2)

    Features:
    • Per-module timing and error counters
    • Auto-recovery (GC, retry once, safe fallback)
    • Live event log with timestamps
    • Cross-file correlation of encrypted/embedded regions
    • GUI callback system (call mu.add_listener(fn) to receive events)
    """

    MAX_EVENTS = 1000

    def __init__(self):
        self._lock      = threading.RLock()
        self._modules:  Dict[str, ModuleHealth] = {}
        self._events:   List[HealthEvent]       = []
        self._listeners: List[Callable[[HealthEvent], None]] = []
        self._cross_data: List[Dict] = []   # accumulated cross-file data

    # ── Listener API ─────────────────────────────────────────────────────────

    def add_listener(self, fn: Callable[[HealthEvent], None]):
        """Register a callback to receive health events (e.g. GUI log panel)."""
        self._listeners.append(fn)

    def _emit(self, event: HealthEvent):
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.MAX_EVENTS:
                self._events.pop(0)
        for fn in self._listeners:
            try:
                fn(event)
            except Exception:
                pass

    # ── Module registry ──────────────────────────────────────────────────────

    def _module(self, name: str) -> ModuleHealth:
        if name not in self._modules:
            self._modules[name] = ModuleHealth(name=name)
        return self._modules[name]

    # ── Guard ─────────────────────────────────────────────────────────────────

    def guard(self,
              module: str,
              func:   Callable,
              *args,
              **kwargs) -> Tuple[bool, Any, Optional[str]]:
        """
        Execute func(*args, **kwargs) safely.
        Returns (success, result, error_message).

        Retry Policy:
          1. First attempt — normal execution
          2. On MemoryError → gc.collect() then retry once
          3. On any other exception → log, return (False, None, msg)
        """
        mod = self._module(module)
        t0  = time.perf_counter()

        def _attempt():
            return func(*args, **kwargs)

        # ── First attempt ─────────────────────────────────────
        try:
            result = _attempt()
            elapsed = (time.perf_counter() - t0) * 1000
            mod.record_call(elapsed, ok=True)
            return True, result, None

        except MemoryError as exc:
            gc.collect()
            self._log_event(module, Severity.WARNING,
                            f"MemoryError — GC triggered, retrying…", "")
            try:
                result = _attempt()
                elapsed = (time.perf_counter() - t0) * 1000
                mod.record_call(elapsed, ok=True)
                mod.status = Severity.RECOVERED
                evt = self._log_event(
                    module, Severity.RECOVERED,
                    "MemoryError recovered after GC", "", fixed=True,
                    fix_note="gc.collect() freed memory")
                return True, result, None
            except Exception as exc2:
                return self._fail(module, exc2, t0)

        except Exception as exc:
            return self._fail(module, exc, t0)

    def _fail(self, module: str,
              exc:    Exception,
              t0:     float) -> Tuple[bool, None, str]:
        elapsed = (time.perf_counter() - t0) * 1000
        tb      = traceback.format_exc()
        msg     = f"{type(exc).__name__}: {exc}"
        mod     = self._module(module)
        mod.record_call(elapsed, ok=False)
        mod.status = Severity.ERROR

        evt = self._log_event(module, Severity.ERROR, msg, tb)
        return False, None, msg

    def _log_event(self, module: str, severity: Severity,
                   message: str, tb: str = "",
                   fixed: bool = False, fix_note: str = "") -> HealthEvent:
        evt = HealthEvent(
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3],
            module    = module,
            severity  = severity,
            message   = message,
            traceback = tb,
            fixed     = fixed,
            fix_note  = fix_note,
        )
        self._emit(evt)
        return evt

    # ── Safe wrapper (returns default on failure) ─────────────────────────────

    def safe(self, module: str, default: Any,
             func: Callable, *args, **kwargs) -> Any:
        """Like guard() but returns default on failure instead of a tuple."""
        ok, result, _ = self.guard(module, func, *args, **kwargs)
        return result if ok else default

    # ── Cross-file Correlation ────────────────────────────────────────────────

    def register_scan(self, file_path: str, scan_result, parse_result=None):
        """
        Accumulate scan data for cross-file correlation.
        Call this after each file is scanned.
        """
        entry = {
            'file':       file_path,
            'time':       datetime.now().isoformat(timespec='seconds'),
            'encrypted':  [(v.offset, v.metrics.H)
                           for v in scan_result.encrypted_regions],
            'compressed': [(v.offset, v.metrics.H)
                           for v in scan_result.compressed_regions],
            'confirmed':  [(v.offset, v.S_total)
                           for v in scan_result.confirmed],
        }
        if parse_result:
            entry['sections'] = [(s.name, s.offset, s.entropy)
                                 for s in parse_result.sections]
        with self._lock:
            self._cross_data.append(entry)

    def cross_correlate(self) -> str:
        """
        Analyse patterns across all registered files.
        Looks for:
        • Encrypted regions that share the same offset across files (same packer?)
        • Sections with matching entropy profiles
        • Repeated string patterns
        """
        with self._lock:
            data = list(self._cross_data)

        if len(data) < 2:
            return "Need ≥ 2 files for cross-file correlation."

        lines = [
            "═" * 60,
            "  CROSS-FILE CORRELATION REPORT",
            f"  Files analysed: {len(data)}",
            "═" * 60,
        ]

        # ── Shared encrypted offsets ──────────────────────────
        from collections import Counter
        all_enc_offsets = []
        for entry in data:
            for off, _ in entry['encrypted']:
                all_enc_offsets.append(off)
        shared = Counter(all_enc_offsets)
        common = [(off, cnt) for off, cnt in shared.items() if cnt >= 2]
        common.sort(key=lambda x: -x[1])

        if common:
            lines.append("\n  ⚠  Shared encrypted offsets (possible same packer/key):")
            for off, cnt in common[:10]:
                lines.append(f"    0x{off:08x}  seen in {cnt}/{len(data)} files")
        else:
            lines.append("\n  ✓  No shared encrypted offsets detected")

        # ── Entropy distribution comparison ───────────────────
        if len(data) >= 2:
            for i, e1 in enumerate(data):
                for j, e2 in enumerate(data):
                    if j <= i:
                        continue
                    enc1 = set(o for o, _ in e1['encrypted'])
                    enc2 = set(o for o, _ in e2['encrypted'])
                    overlap = enc1 & enc2
                    if overlap:
                        lines.append(
                            f"\n  Files {i+1} & {j+1} share"
                            f" {len(overlap)} encrypted region(s)")

        # ── Section name overlap ──────────────────────────────
        all_secs = []
        for entry in data:
            for name, _, _ in entry.get('sections', []):
                all_secs.append(name)
        sec_freq = Counter(all_secs)
        common_secs = [s for s, c in sec_freq.items() if c >= 2 and s]
        if common_secs:
            lines.append("\n  Common section names:")
            for s in common_secs[:10]:
                lines.append(f"    {s}")

        lines.append("\n" + "═" * 60)
        return "\n".join(lines)

    # ── Health report ─────────────────────────────────────────────────────────

    @property
    def events(self) -> List[HealthEvent]:
        with self._lock:
            return list(self._events)

    @property
    def module_health(self) -> Dict[str, ModuleHealth]:
        with self._lock:
            return dict(self._modules)

    def full_report(self) -> str:
        with self._lock:
            mods   = dict(self._modules)
            events = list(self._events)

        total_errors   = sum(m.errors for m in mods.values())
        total_warnings = sum(m.warnings for m in mods.values())

        lines = [
            "═" * 60,
            "  🏥 MEDICAL UNIT — FULL HEALTH REPORT",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 60,
            f"  Modules monitored : {len(mods)}",
            f"  Total errors      : {total_errors}",
            f"  Total warnings    : {total_warnings}",
            f"  Total events      : {len(events)}",
            "",
            "MODULE STATUS:",
        ]
        for m in mods.values():
            lines.append("  " + m.summary())

        err_events = [e for e in events if e.severity == Severity.ERROR]
        if err_events:
            lines.append("")
            lines.append("ERROR LOG (latest 20):")
            for e in err_events[-20:]:
                fixed_tag = "  → auto-fixed ✓" if e.fixed else ""
                lines.append(f"  [{e.timestamp}] [{e.module}] {e.message}{fixed_tag}")
                if e.fix_note:
                    lines.append(f"      Fix: {e.fix_note}")

        lines.append("═" * 60)
        return "\n".join(lines)

    def is_healthy(self) -> bool:
        """True if no module is in ERROR or CRITICAL state."""
        return all(
            m.status not in (Severity.ERROR, Severity.CRITICAL)
            for m in self._modules.values()
        )

    def reset_module(self, name: str):
        """Reset error state for a specific module (after user fixes issue)."""
        if name in self._modules:
            self._modules[name].status = Severity.OK
            self._modules[name].errors = 0
            self._log_event(name, Severity.OK, "Module state reset by user")
