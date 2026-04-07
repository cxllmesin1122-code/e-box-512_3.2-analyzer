"""
E-BOX 512 V3.2 — Final Sealed Protocol
Deterministic Binary Decision System  (Production-Grade)
Author: Omsin  |  GPU: GTX 850M CuPy / NumPy fallback
"""

from __future__ import annotations
import concurrent.futures
import math
import os
import time
import numpy as np
from binary_parser import parse_binary
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
import threading

# ─── GPU Acceleration Setup ─────────────────────────────────────────────────
_GPU_LOCK = threading.Lock()
GPU_AVAILABLE = False
cp = None

def _init_gpu():
    global GPU_AVAILABLE, cp
    try:
        import cupy as _cp
        # Probe: allocate small array to confirm GPU works
        _cp.array([1, 2, 3], dtype=_cp.float32)
        cp = _cp
        GPU_AVAILABLE = True
        print("[GPU] CuPy GPU acceleration ENABLED")
    except ImportError as e:
        print(f"[GPU] CuPy not available ({e}), falling back to NumPy")
        import numpy as _np
        cp = _np
        GPU_AVAILABLE = False
    except Exception as e:
        print(f"[GPU] GPU initialization failed ({type(e).__name__}: {e}), using NumPy")
        import numpy as _np
        cp = _np
        GPU_AVAILABLE = False

try:
    _init_gpu()
except (KeyboardInterrupt, SystemExit):
    print("[GPU] GPU initialization interrupted, using NumPy")
    import numpy as _np
    cp = _np
    GPU_AVAILABLE = False

XP = cp       # Runtime array library (CuPy or NumPy)
NP = np       # Always NumPy for final Python-side ops


# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass
class WindowMetrics:
    """All 6 statistical measures for one analysis window."""
    offset:       int   = 0
    window_size:  int   = 512
    # Part 1 – mathematical units
    H:            float = 0.0   # Shannon entropy (bits)
    delta_H:      float = 0.0   # ΔH_norm = |H_n - H_{n-1}| / 8
    chi2_score:   float = 0.0   # χ²_score = clip(1/(1+χ²), 0, 1)
    kl_inv:       float = 0.0   # Smoothed KL⁻¹ (uniformity score)
    R_norm:       float = 0.0   # Z-normalised autocorrelation peak
    S_spec:       float = 0.0   # Band-limited spectral dominance
    # Derived / gate scores
    S_pre:        float = 0.0   # Pre-score (Gate 3)
    S_total:      float = 0.0   # Final total score (Gate 5)
    CV:           float = 0.0   # Stability index (Gate 4)


@dataclass
class GateVerdict:
    """Outcome from the 5-gate pipeline for one window."""
    offset:      int   = 0
    gate_passed: int   = 0      # highest gate reached (1-5)
    verdict:     str   = "DISCARD"
    # DISCARD | ENCRYPTED | COMPRESSED | LOW_INTEREST | CANDIDATE | CONFIRMED
    reason:      str   = ""
    metrics:     WindowMetrics = field(default_factory=WindowMetrics)
    S_total:     float = 0.0
    percentile:  float = 0.0    # filled after full-file scan


@dataclass
class ScanResult:
    """Aggregated result of scanning a complete binary region."""
    total_windows:     int   = 0
    confirmed:         List[GateVerdict] = field(default_factory=list)
    encrypted_regions: List[GateVerdict] = field(default_factory=list)
    compressed_regions:List[GateVerdict] = field(default_factory=list)
    candidates:        List[GateVerdict] = field(default_factory=list)
    discarded:         int   = 0
    threshold_T:       float = 0.0
    gpu_used:          bool  = False
    errors:            List[str] = field(default_factory=list)


# ─── EBox512 Core ────────────────────────────────────────────────────────────

ALPHA   = 1e-6   # Laplace smoothing
EPSILON = 1e-10  # Division guard


class EBox512:
    """
    E-BOX 512 V3.2 – 5-gate deterministic pipeline.
    Thread-safe; can run on CuPy (GPU) or NumPy (CPU).
    """

    def __init__(self,
                 window_size:   int   = 512,
                 step_size:     int   = 256,
                 stability_win: int   = 5,
                 vram_cap_mb:   float = 3500.0):
        self.window_size   = window_size
        self.step_size     = step_size
        self.stability_win = stability_win
        self.vram_cap_bytes = int(vram_cap_mb * 1024 * 1024)
        self._xp = XP

    # ── Part 1: Mathematical Units ───────────────────────────────────────────

    @staticmethod
    def entropy(data: bytes) -> float:
        """Shannon entropy H (bits, range 0-8)."""
        if not data:
            return 0.0
        xp = XP if GPU_AVAILABLE else NP
        arr = xp.frombuffer(data, dtype=xp.uint8)
        counts = xp.bincount(arr, minlength=256).astype(xp.float64)
        if GPU_AVAILABLE:
            counts = NP.array(counts.get(), dtype=NP.float64)
        probs = counts / len(data)
        probs = probs[probs > 0]
        return float(-NP.sum(probs * NP.log2(probs)))

    @staticmethod
    def entropy_gradient(H_n: float, H_prev: float) -> float:
        """ΔH_norm = |H_n − H_{n-1}| / 8"""
        return abs(H_n - H_prev) / 8.0

    @staticmethod
    def chi2_score(data: bytes) -> float:
        """χ²_score = clip(1/(1+χ²), 0, 1)"""
        xp = XP if GPU_AVAILABLE else NP
        arr = xp.frombuffer(data, dtype=xp.uint8)
        counts = xp.bincount(arr, minlength=256).astype(xp.float64)
        if GPU_AVAILABLE:
            counts = NP.array(counts.get(), dtype=NP.float64)
        expected = len(data) / 256.0
        chi2 = float(NP.sum((counts - expected) ** 2 / expected))
        return float(NP.clip(1.0 / (1.0 + chi2), 0.0, 1.0))

    @staticmethod
    def kl_divergence_inv(data: bytes) -> float:
        """
        Smoothed KL⁻¹.  P_i = (count_i + α) / (N + α·k)
        Returns  1/(1 + KL(P||U))  — higher = more uniform/random.
        """
        N   = len(data)
        k   = 256
        arr = NP.frombuffer(data, dtype=NP.uint8)
        cnt = NP.bincount(arr, minlength=256).astype(NP.float64)
        P   = (cnt + ALPHA) / (N + ALPHA * k)
        # KL(P || Uniform) = Σ P·log(P·k)
        kl  = float(NP.sum(P * NP.log(P * k + EPSILON)))
        return 1.0 / (1.0 + max(kl, 0.0))

    def autocorr_normalized(self, data: bytes) -> float:
        """
        Z-normalised autocorrelation peak.
        R_norm = (R_peak − μ_R) / (σ_R + ε)
        Uses GPU (CuPy) when available.
        """
        xp  = self._xp
        arr = xp.frombuffer(data, dtype=xp.uint8).astype(xp.float32)
        arr = arr - xp.mean(arr)
        n   = len(arr)

        # Via FFT: power spectrum → IFFT → autocorrelation
        F    = xp.fft.fft(arr, n=2 * n)
        pwr  = F * xp.conj(F)
        ac   = xp.real(xp.fft.ifft(pwr))[:n]
        denom = float(ac[0]) if hasattr(ac[0], '__float__') else float(xp.asnumpy(ac[0]))
        if abs(denom) < EPSILON:
            return 0.0
        ac   = ac / (denom + EPSILON)

        # Pull to NumPy for stats
        ac_np = NP.array(ac[1:].tolist() if GPU_AVAILABLE else ac[1:],
                         dtype=NP.float32)
        peaks = NP.abs(ac_np)
        R_peak = float(NP.max(peaks))
        mu_R   = float(NP.mean(peaks))
        sig_R  = float(NP.std(peaks))
        return (R_peak - mu_R) / (sig_R + EPSILON)

    def spectral_score(self, data: bytes) -> float:
        """
        Band-limited spectral dominance.
        S_spec = Φ_max / ΣΦ  (f=0 excluded)
        """
        xp   = self._xp
        arr  = xp.frombuffer(data, dtype=xp.uint8).astype(xp.float32)
        F    = xp.fft.fft(arr)
        ps   = xp.abs(F[1:]) ** 2   # Ignore DC

        if GPU_AVAILABLE:
            ps_np = NP.array(ps.tolist(), dtype=NP.float64)
        else:
            ps_np = NP.asarray(ps, dtype=NP.float64)

        total = float(NP.sum(ps_np))
        if total < EPSILON:
            return 0.0
        return float(NP.max(ps_np)) / total

    @staticmethod
    def stability_cv(score_window: List[float]) -> float:
        """
        CV = σ_S / (μ_S + ε)   over ±stability_win windows.
        Fallback to 0 when μ_S < 0.01 (empty region guard).
        """
        if len(score_window) < 2:
            return 0.0
        arr  = NP.array(score_window, dtype=NP.float64)
        mu_S = float(NP.mean(arr))
        if mu_S < 0.01:
            return 0.0                  # Fallback: skip CV
        sig_S = float(NP.std(arr))
        return sig_S / (mu_S + EPSILON)

    # ── Part 2: Five-Gate Pipeline ───────────────────────────────────────────

    def _gate1(self, H: float, delta_hist: List[float]) -> Optional[str]:
        """Gate 1 – Fast Filter (discard trivial data)."""
        if H < 3.0:
            return f"H={H:.3f} < 3.0 → trivial"
        if len(delta_hist) >= 10:
            if all(d < 0.01 for d in delta_hist[-10:]):
                return f"ΔH flat ≥10 windows → uniform block"
        return None

    def _gate2(self, H: float, chi2: float,
               R_norm: float) -> Optional[str]:
        """Gate 2 – Classifier (encrypted vs compressed vs candidate)."""
        if H > 7.5 and chi2 > 0.8 and R_norm <= 0:
            return "ENCRYPTED"
        if H > 7.5 and chi2 < 0.5 and R_norm > 2.0:
            return "COMPRESSED"
        return None

    def _gate3(self, R_norm: float, kl_inv: float,
               chi2: float, delta_H: float) -> Tuple[float, bool]:
        """
        Gate 3 – Pre-Scorer.
        S_pre_raw = 0.35·R + 0.25·KL⁻¹ + 0.15·χ² + 0.15·ΔH
        S_pre     = S_pre_raw / 0.9
        Returns (S_pre, run_fft)
        """
        S_pre_raw = (0.35 * R_norm + 0.25 * kl_inv +
                     0.15 * chi2    + 0.15 * delta_H)
        S_pre = S_pre_raw / 0.9
        run_fft = S_pre > 0.5
        return float(S_pre), run_fft

    def run_window(self,
                   data:         bytes,
                   offset:       int,
                   prev_H:       float,
                   delta_hist:   List[float],
                   score_window: List[float]) -> GateVerdict:
        """
        Full 5-gate pipeline for a single window.
        score_window used for Gate-4 CV (caller maintains it).
        """
        m = WindowMetrics(offset=offset, window_size=len(data))
        v = GateVerdict(offset=offset, metrics=m)

        if len(data) < 16:
            v.verdict = "DISCARD"
            v.reason  = "Window too small"
            return v

        # ── Measure ──────────────────────────────────────────────
        m.H       = self.entropy(data)
        m.delta_H = self.entropy_gradient(m.H, prev_H)

        # ── Gate 1 ───────────────────────────────────────────────
        fail1 = self._gate1(m.H, delta_hist + [m.delta_H])
        if fail1:
            v.verdict     = "DISCARD"
            v.reason      = fail1
            v.gate_passed = 1
            return v
        v.gate_passed = 1

        # ── Gate 2 ───────────────────────────────────────────────
        m.chi2_score = self.chi2_score(data)
        m.R_norm     = self.autocorr_normalized(data)
        m.kl_inv     = self.kl_divergence_inv(data)

        g2 = self._gate2(m.H, m.chi2_score, m.R_norm)
        if g2 == "ENCRYPTED":
            v.verdict     = "ENCRYPTED"
            v.reason      = f"H={m.H:.2f} χ²={m.chi2_score:.2f} R={m.R_norm:.2f}"
            v.gate_passed = 2
            return v
        if g2 == "COMPRESSED":
            v.verdict     = "COMPRESSED"
            v.reason      = f"H={m.H:.2f} χ²={m.chi2_score:.2f} R={m.R_norm:.2f}"
            v.gate_passed = 2
            return v
        v.gate_passed = 2

        # ── Gate 3 ───────────────────────────────────────────────
        m.S_pre, run_fft = self._gate3(
            m.R_norm, m.kl_inv, m.chi2_score, m.delta_H)

        if m.S_pre <= 0.5:
            v.verdict     = "LOW_INTEREST"
            v.reason      = f"S_pre={m.S_pre:.3f} ≤ 0.5"
            v.gate_passed = 3
            return v

        if run_fft:
            m.S_spec = self.spectral_score(data)
        v.gate_passed = 3

        # ── Gate 4 ───────────────────────────────────────────────
        m.CV = self.stability_cv(score_window)
        if m.CV >= 0.05 and len(score_window) >= 3:
            v.verdict     = "UNSTABLE"
            v.reason      = f"CV={m.CV:.4f} ≥ 0.05 (signal unstable)"
            v.gate_passed = 4
            return v
        v.gate_passed = 4

        # ── Gate 5 ───────────────────────────────────────────────
        m.S_total = m.S_pre + 0.10 * m.S_spec
        v.S_total     = m.S_total
        v.verdict     = "CANDIDATE"
        v.reason      = f"S_total={m.S_total:.3f}, CV={m.CV:.4f} (threshold pending)"
        v.gate_passed = 5
        return v

    # ── Full File Scan ───────────────────────────────────────────────────────

    def scan(self, data: bytes,
             progress_cb=None,
             medical_unit=None) -> ScanResult:
        """
        Slide window over entire binary.
        After full scan, compute T_final = max(0.75, P95) and promote
        CANDIDATE → CONFIRMED.

        progress_cb(pct: float, msg: str)  optional UI callback.
        """
        result = ScanResult(gpu_used=GPU_AVAILABLE)
        total  = len(data)
        if total == 0:
            result.errors.append("Empty data")
            return result

        all_verdicts:  List[GateVerdict] = []
        delta_hist:    List[float]       = []
        score_window:  List[float]       = []
        prev_H:        float             = 4.0    # neutral prior

        n_windows = max(1, (total - self.window_size) // self.step_size + 1)
        result.total_windows = n_windows

        for idx in range(n_windows):
            off   = idx * self.step_size
            chunk = data[off: off + self.window_size]
            if len(chunk) < 16:
                break

            def _run(c=chunk, o=off, ph=prev_H,
                     dh=list(delta_hist), sw=list(score_window)):
                return self.run_window(c, o, ph, dh, sw)

            if medical_unit:
                ok, verd, err = medical_unit.guard("EBox512", _run)
                if not ok:
                    result.errors.append(f"Window@0x{off:08x}: {err}")
                    continue
            else:
                verd = _run()

            all_verdicts.append(verd)
            prev_H = verd.metrics.H
            delta_hist.append(verd.metrics.delta_H)
            if len(delta_hist) > 20:
                delta_hist.pop(0)

            if verd.S_total > 0:
                score_window.append(verd.S_total)
            if len(score_window) > self.stability_win * 2 + 1:
                score_window.pop(0)

            if progress_cb and idx % 50 == 0:
                pct = (idx / n_windows) * 100
                progress_cb(pct, f"Window {idx}/{n_windows} @ 0x{off:08x}")

        # ── Post-scan: determine adaptive threshold ───────────────
        all_scores = [v.S_total for v in all_verdicts if v.S_total > 0]
        if all_scores:
            p95 = float(NP.percentile(all_scores, 95))
        else:
            p95 = 0.0
        T_final = max(0.75, p95)
        result.threshold_T = T_final

        # ── Classify final verdicts ───────────────────────────────
        for v in all_verdicts:
            v.percentile = T_final
            if v.verdict == "ENCRYPTED":
                result.encrypted_regions.append(v)
            elif v.verdict == "COMPRESSED":
                result.compressed_regions.append(v)
            elif v.verdict in ("CANDIDATE",) and v.S_total > T_final and v.metrics.CV < 0.05:
                v.verdict = "CONFIRMED"
                v.reason  = (f"🎯 CONFIRMED  S_total={v.S_total:.4f} > T={T_final:.4f}"
                             f"  CV={v.metrics.CV:.4f}")
                result.confirmed.append(v)
            elif v.verdict == "CANDIDATE":
                result.candidates.append(v)
            else:
                result.discarded += 1

        if progress_cb:
            progress_cb(100.0, "Scan complete")

        return result

    # ── Correlation: encrypted ↔ structural ──────────────────────────────────

    @staticmethod
    def correlate_encrypted_with_sections(
            scan_result: ScanResult,
            sections: list) -> List[Dict[str, Any]]:
        """
        Map encrypted regions back to binary sections.
        Returns list of correlation dicts.
        """
        correlations = []
        for enc in scan_result.encrypted_regions:
            for sec in sections:
                sec_start = getattr(sec, 'offset', 0)
                sec_end   = sec_start + getattr(sec, 'size', 0)
                if sec_start <= enc.offset <= sec_end:
                    correlations.append({
                        'enc_offset':  enc.offset,
                        'enc_hex':     hex(enc.offset),
                        'section':     getattr(sec, 'name', '?'),
                        'sec_range':   f"0x{sec_start:08x}–0x{sec_end:08x}",
                        'H':           enc.metrics.H,
                        'chi2':        enc.metrics.chi2_score,
                    })
                    break
        return correlations

    # ── Summary ──────────────────────────────────────────────────────────────

    @staticmethod
    def summary_text(scan_result: ScanResult) -> str:
        r = scan_result
        lines = [
            "═" * 60,
            "  E-BOX 512 V3.2 — SCAN SUMMARY",
            "═" * 60,
            f"  GPU accelerated : {'YES (CuPy)' if r.gpu_used else 'NO  (NumPy fallback)'}",
            f"  Total windows   : {r.total_windows}",
            f"  Threshold T_95  : {r.threshold_T:.4f}",
            "",
            f"  🎯 CONFIRMED        : {len(r.confirmed)}",
            f"  🔐 ENCRYPTED        : {len(r.encrypted_regions)}",
            f"  📦 COMPRESSED       : {len(r.compressed_regions)}",
            f"  🔎 CANDIDATES       : {len(r.candidates)}",
            f"  🗑  DISCARDED       : {r.discarded}",
        ]
        if r.errors:
            lines += ["", f"  ⚠  Errors: {len(r.errors)}"]
        lines.append("═" * 60)

        if r.confirmed:
            lines.append("\n  CONFIRMED REGIONS:")
            for v in r.confirmed[:20]:
                lines.append(f"    0x{v.offset:08x}  {v.reason}")

        if r.encrypted_regions:
            lines.append("\n  ENCRYPTED REGIONS (top 10):")
            for v in r.encrypted_regions[:10]:
                lines.append(
                    f"    0x{v.offset:08x}  H={v.metrics.H:.2f}"
                    f"  χ²={v.metrics.chi2_score:.2f}"
                    f"  R={v.metrics.R_norm:.2f}")

        return "\n".join(lines)


# ─── Malware Detector ────────────────────────────────────────────────────────

@dataclass
class MalwareVerdict:
    offset:      int   = 0
    type:        str   = "UNKNOWN"  # MALWARE | ROOTKIT | AIMBOT | ANTICHEAT | CLEAN
    confidence:  float = 0.0       # 0.0 - 1.0
    reason:      str   = ""
    metrics:     Dict[str, float] = field(default_factory=dict)
    # Per-category scores (0.0-1.0) for deeper explanation
    scores:      Dict[str, float] = field(default_factory=dict)
    # Probability that the detected payload will execute/be operational
    operational_prob: float = 0.0
    # Human-readable explanation (detailed)
    explanation:  str   = ""


@dataclass
class MalwareScanResult:
    total_scanned: int = 0
    malware:       List[MalwareVerdict] = field(default_factory=list)
    rootkit:       List[MalwareVerdict] = field(default_factory=list)
    aimbot:        List[MalwareVerdict] = field(default_factory=list)
    anticheat:     List[MalwareVerdict] = field(default_factory=list)
    virus:         List[MalwareVerdict] = field(default_factory=list)
    clean:         int = 0
    errors:        List[str] = field(default_factory=list)
    # Aggregate confidences across the entire file per category
    overall_confidences: Dict[str, float] = field(default_factory=dict)


class MalwareDetector:
    """
    Advanced malware, rootkit, aimbot, and anti-cheat detection using
    comprehensive mathematical models and signatures.
    """

    # Known signatures (byte patterns) for common malware/anti-cheat
    MALWARE_SIGNATURES = {
        'malware': [
            b'\xE8\x00\x00\x00\x00\x5D\x81\xED',  # Common shellcode prologue
            b'\x55\x8B\xEC\x83\xEC\x10\x53\x56',  # Windows malware pattern
            b'\x31\xC0\x31\xDB\x31\xC9\x31\xD2',  # Linux rootkit init
        ],
        'virus': [
            b'UPX!',                                 # UPX-packed sections (common packer)
            b'Rar!',                                 # RAR SFX header (packed)
            b'PK\x03\x04',                         # Embedded ZIP-based payloads
        ],
        'rootkit': [
            b'\xB8\x01\x00\x00\x00\xCD\x80',      # syscall hook pattern
            b'\x0F\x05\x48\x89\xC7\x48\x89\xF0',  # syscall interception
        ],
        'aimbot': [
            b'\xF3\x0F\x10\x05',  # SSE movss (common in aim calculations)
            b'\x66\x0F\x6E\xC0',  # movd xmm0, eax (vector math)
        ],
        'anticheat': [
            b'\xE8\x00\x00\x00\x00\x8B\x45\xFC',  # AC integrity check
            b'\x55\x89\xE5\x83\xEC\x18\xC7\x45',  # Kernel-mode AC pattern
        ],
    }

    # Known offsets for popular games (example, can be expanded)
    KNOWN_OFFSETS = {
        'csgo': {
            'aimbot': [0x12345678, 0x87654321],  # Example offsets
            'anticheat': [0xABCDEF00],
        },
        'valorant': {
            'aimbot': [0x11111111],
            'anticheat': [0x22222222],
        },
    }

    def __init__(self, window_size: int = 512, step_size: int = 256):
        self.window_size = window_size
        self.step_size = step_size

    def kolmogorov_smirnov_test(self, data: bytes, reference: bytes) -> float:
        """
        KS test: measures maximum difference between empirical distributions.
        Returns KS statistic (0-1), higher = more different.
        """
        def ecdf(arr):
            sorted_arr = NP.sort(arr)
            yvals = NP.arange(1, len(sorted_arr)+1) / len(sorted_arr)
            return sorted_arr, yvals

        arr1 = NP.frombuffer(data, dtype=NP.uint8)
        arr2 = NP.frombuffer(reference, dtype=NP.uint8)

        x1, y1 = ecdf(arr1)
        x2, y2 = ecdf(arr2)

        # Interpolate and find max diff
        all_x = NP.unique(NP.concatenate([x1, x2]))
        y1_interp = NP.interp(all_x, x1, y1, left=0, right=1)
        y2_interp = NP.interp(all_x, x2, y2, left=0, right=1)
        ks_stat = NP.max(NP.abs(y1_interp - y2_interp))
        return float(ks_stat)

    def fourier_periodicity(self, data: bytes) -> float:
        """
        Detect periodic patterns using Fourier transform.
        Returns dominant frequency strength (0-1).
        Useful for aimbot timing loops or repetitive hooks.
        """
        arr = NP.frombuffer(data, dtype=NP.uint8).astype(NP.float64)
        arr = arr - NP.mean(arr)

        fft = NP.fft.fft(arr)
        power = NP.abs(fft)**2
        power[0] = 0  # Remove DC component

        # Find peak frequency
        peak_idx = NP.argmax(power[1:]) + 1
        total_power = NP.sum(power)
        if total_power < EPSILON:
            return 0.0
        return float(power[peak_idx] / total_power)

    def markov_chain_entropy(self, data: bytes, order: int = 2) -> float:
        """
        Markov chain transition entropy.
        Lower entropy = more predictable patterns (malware signatures).
        """
        if len(data) < order + 1:
            return 8.0

        transitions = {}
        for i in range(len(data) - order):
            state = tuple(data[i:i+order])
            next_byte = data[i+order]
            if state not in transitions:
                transitions[state] = NP.zeros(256, dtype=NP.int32)
            transitions[state][next_byte] += 1

        total_entropy = 0.0
        total_states = len(transitions)

        for state, counts in transitions.items():
            state_total = NP.sum(counts)
            if state_total > 0:
                probs = counts / state_total
                probs = probs[probs > 0]
                entropy = -NP.sum(probs * NP.log2(probs))
                total_entropy += entropy

        return total_entropy / max(total_states, 1)

    def signature_distance(self, data: bytes, signatures: List[bytes]) -> float:
        """
        Minimum Hamming distance to known signatures.
        Returns normalized distance (0-1), lower = closer match.
        """
        if not signatures or not data:
            return 1.0

        data_arr = NP.frombuffer(data, dtype=NP.uint8)
        min_distance = float('inf')

        for sig in signatures:
            sig_len = len(sig)
            if sig_len == 0 or sig_len > data_arr.size:
                continue

            sig_arr = NP.frombuffer(sig, dtype=NP.uint8)

            # Arm vectorized sliding-window with numpy when available
            try:
                windows = NP.lib.stride_tricks.sliding_window_view(data_arr, sig_len)
                xor_vals = NP.bitwise_xor(windows, sig_arr)
                distances = NP.count_nonzero(xor_vals, axis=1)
                d = float(NP.min(distances)) if distances.size else float('inf')
            except Exception:
                # Fallback naive loop with early exit
                d = float('inf')
                for i in range(data_arr.size - sig_len + 1):
                    window = data_arr[i:i+sig_len]
                    distance = int(NP.count_nonzero(window ^ sig_arr))
                    if distance < d:
                        d = distance
                        if d == 0:
                            break

            if d < min_distance:
                min_distance = d
                if d == 0:
                    break

        if min_distance == float('inf'):
            return 1.0

        max_possible = 8 * max(len(s) for s in signatures if len(s) > 0)
        return min_distance / max_possible

    def detect_window(self, data: bytes, offset: int) -> MalwareVerdict:
        """
        Analyze a single window for malware characteristics.
        Uses ensemble of mathematical models.
        """
        verdict = MalwareVerdict(offset=offset)

        # Use deterministic reference for KS test (avoid RNG overhead)
        ref_data = bytes((i & 0xFF for i in range(len(data))))

        # Compute metrics
        H = EBox512.entropy(data)

        # Ferret out very clean / very random blocks early
        if H < 2.0 or H > 7.8:
            verdict.type = 'CLEAN'
            verdict.confidence = 0.01
            verdict.reason = f'Entropy extreme (H={H:.2f})'
            verdict.metrics = {'entropy': H}
            return verdict

        ks_stat = self.kolmogorov_smirnov_test(data, ref_data)

        periodicity = self.fourier_periodicity(data)

        # Only compute Markov entropy when needed
        markov_ent = self.markov_chain_entropy(data)

        # Signature distances (including virus/packer heuristics)
        mal_dist = self.signature_distance(data, self.MALWARE_SIGNATURES.get('malware', []))
        root_dist = self.signature_distance(data, self.MALWARE_SIGNATURES.get('rootkit', []))
        aim_dist = self.signature_distance(data, self.MALWARE_SIGNATURES.get('aimbot', []))
        ac_dist = self.signature_distance(data, self.MALWARE_SIGNATURES.get('anticheat', []))
        virus_dist = self.signature_distance(data, self.MALWARE_SIGNATURES.get('virus', []))

        # Normalised metrics (0-1)
        h_norm = max(0.0, min(1.0, H / 8.0))
        markov_norm = max(0.0, min(1.0, (8.0 - markov_ent) / 8.0))
        mal_match = max(0.0, min(1.0, 1.0 - mal_dist))
        root_match = max(0.0, min(1.0, 1.0 - root_dist))
        aim_match = max(0.0, min(1.0, 1.0 - aim_dist))
        ac_match = max(0.0, min(1.0, 1.0 - ac_dist))
        virus_match = max(0.0, min(1.0, 1.0 - virus_dist))

        verdict.metrics = {
            'entropy': H,
            'ks_stat': ks_stat,
            'periodicity': periodicity,
            'markov_entropy': markov_ent,
            'malware_dist': mal_dist,
            'rootkit_dist': root_dist,
            'aimbot_dist': aim_dist,
            'anticheat_dist': ac_dist,
            'virus_dist': virus_dist,
        }

        # Per-category scoring (weighted combination of signals)
        scores = {}
        scores['malware'] = float(max(0.0, min(1.0,
            0.40 * h_norm + 0.35 * ks_stat + 0.25 * mal_match)))
        scores['rootkit'] = float(max(0.0, min(1.0,
            0.35 * periodicity + 0.35 * root_match + 0.30 * markov_norm)))
        scores['aimbot'] = float(max(0.0, min(1.0,
            0.50 * periodicity + 0.30 * aim_match + 0.20 * h_norm)))
        scores['anticheat'] = float(max(0.0, min(1.0,
            0.40 * ac_match + 0.30 * (1.0 - ks_stat) + 0.30 * (1.0 - h_norm))))
        scores['virus'] = float(max(0.0, min(1.0,
            0.35 * h_norm + 0.35 * virus_match + 0.20 * ks_stat + 0.10 * markov_norm)))

        # Attach per-category scores for explanation
        verdict.scores = scores

        # Choose the best category and set confidence
        best_type = max(scores.items(), key=lambda x: x[1])[0]
        best_score = scores.get(best_type, 0.0)

        # Operational probability heuristics: prefer higher markov predictability
        operational_prob = float(max(0.0, min(1.0, best_score * (0.6 + 0.4 * markov_norm))))

        # Thresholding: require a minimum score to call it non-clean
        threshold = 0.45
        if best_score < threshold:
            verdict.type = 'CLEAN'
            verdict.confidence = 0.01
            verdict.operational_prob = 0.0
            verdict.explanation = f"No strong signals: top_score={best_score:.3f}"
            return verdict

        verdict.type = best_type.upper()
        verdict.confidence = float(min(1.0, best_score))
        verdict.operational_prob = operational_prob
        verdict.reason = (f"Top={best_type} score={best_score:.3f} H={H:.2f}"
                          f" KS={ks_stat:.2f} Period={periodicity:.2f}")
        verdict.explanation = (
            f"scores={scores} | markov_norm={markov_norm:.3f} | "
            f"operational_prob={operational_prob:.3f}")

        return verdict

    def scan_binary(self, data: bytes, progress_cb=None) -> MalwareScanResult:
        """
        Full malware scan using sliding window analysis.
        """
        result = MalwareScanResult()
        total = len(data)
        if total == 0:
            return result

        n_windows = max(1, (total - self.window_size) // self.step_size + 1)
        result.total_scanned = n_windows

        offsets = [i * self.step_size for i in range(n_windows)]
        workers = min(8, (os.cpu_count() or 2))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.detect_window,
                                        data[offset:offset + self.window_size],
                                        offset): idx
                       for idx, offset in enumerate(offsets)}

            done = 0
            for fut in concurrent.futures.as_completed(futures):
                done += 1
                idx = futures[fut]
                try:
                    verdict = fut.result()
                except Exception as ex:
                    result.errors.append(str(ex))
                    continue

                if verdict.type == 'MALWARE':
                    result.malware.append(verdict)
                elif verdict.type == 'ROOTKIT':
                    result.rootkit.append(verdict)
                elif verdict.type == 'AIMBOT':
                    result.aimbot.append(verdict)
                elif verdict.type == 'ANTICHEAT':
                    result.anticheat.append(verdict)
                elif verdict.type == 'VIRUS':
                    result.virus.append(verdict)
                else:
                    result.clean += 1

                if progress_cb and done % max(1, n_windows // 100 + 1) == 0:
                    pct = (done / n_windows) * 100.0
                    progress_cb(pct, f"Malware scan: {done}/{n_windows}")

        if progress_cb:
            progress_cb(100.0, "Malware scan complete")

        return result

    def analyze_file(self, data: bytes, parse_result=None,
                     progress_cb=None, medical_unit=None) -> MalwareScanResult:
        """
        High-level file analysis combining sliding-window signals with
        structural signals (imports, strings, section entropies).
        Returns MalwareScanResult with `overall_confidences` filled.
        """
        # Structural parse
        pr = parse_result
        if pr is None:
            try:
                pr = parse_binary(data)
            except Exception:
                pr = None

        # Window-level scan
        window_result = self.scan_binary(data, progress_cb=progress_cb)

        # Aggregate window confidences per category
        def avg_conf(list_of_verdicts):
            if not list_of_verdicts:
                return 0.0
            return float(sum(v.confidence for v in list_of_verdicts) / len(list_of_verdicts))

        win_conf = {
            'malware': avg_conf(window_result.malware),
            'rootkit': avg_conf(window_result.rootkit),
            'aimbot':  avg_conf(window_result.aimbot),
            'anticheat': avg_conf(window_result.anticheat),
            'virus':   avg_conf(window_result.virus) if hasattr(window_result, 'virus') else 0.0,
        }

        # Structural heuristics
        strings = pr.strings if pr else []
        if pr and getattr(pr, 'deobfuscated_strings', None):
            strings = list(dict.fromkeys(strings + pr.deobfuscated_strings))
        imports = pr.imports if pr else []
        sections = pr.sections if pr else []

        def contains_any(haystack, keywords):
            hk = [h.lower() for h in haystack]
            return sum(1 for k in keywords if any(k in s for s in hk))

        malware_apis = ['virtualalloc', 'writeprocessmemory', 'createremotethread',
                        'openprocess', 'loadlibrary', 'getprocaddress', 'urlindownloadtofile', 'internetopen']
        rootkit_terms = ['syscall', 'rootkit', 'kernel', 'hook', 'modprobe', 'insmod']
        anticheat_terms = ['anticheat', 'ac_client', 'driver', 'kdmapper', 'kernel']
        aimbot_terms = ['aimbot', 'fov', 'smoothing', 'aim', 'target']
        virus_terms = ['autorun', 'mbr', 'bootkit', 'trojan', 'dropper', 'payload']

        import_score = 0.0
        if imports:
            matches = contains_any(imports, malware_apis + rootkit_terms + anticheat_terms)
            import_score = min(1.0, matches / max(1, len(malware_apis)))

        string_score = 0.0
        if strings:
            matches = contains_any(strings, malware_apis + virus_terms + aimbot_terms + anticheat_terms)
            string_score = min(1.0, matches / max(1, len(malware_apis)))

        # High-entropy section fraction
        high_entropy_frac = 0.0
        if sections:
            high = sum(1 for s in sections if getattr(s, 'entropy', 0.0) > 7.0)
            high_entropy_frac = high / len(sections)

        struct_scores = {}
        struct_scores['malware'] = float(min(1.0, 0.5 * import_score + 0.3 * string_score + 0.2 * high_entropy_frac))
        struct_scores['rootkit'] = float(min(1.0, 0.5 * (contains_any(strings, rootkit_terms) > 0) + 0.25 * high_entropy_frac))
        struct_scores['aimbot'] = float(min(1.0, 0.5 * (contains_any(strings, aimbot_terms) > 0) + 0.25 * string_score))
        struct_scores['anticheat'] = float(min(1.0, 0.5 * (contains_any(strings, anticheat_terms) > 0) + 0.25 * string_score))
        struct_scores['virus'] = float(min(1.0, 0.5 * string_score + 0.3 * import_score + 0.2 * high_entropy_frac))

        # Combine window and structural signals (weights)
        final_conf = {}
        for cat in ('malware', 'rootkit', 'aimbot', 'anticheat', 'virus'):
            w = win_conf.get(cat, 0.0)
            s = struct_scores.get(cat, 0.0)
            final_conf[cat] = float(min(1.0, 0.6 * w + 0.4 * s))

        window_result.overall_confidences = final_conf

        # Update each verdict's operational_prob using structural boost
        def boost_verdicts(lst, cat):
            for v in lst:
                structural = struct_scores.get(cat, 0.0)
                v.operational_prob = float(min(1.0, v.confidence * (0.6 + 0.4 * structural)))
                v.explanation = v.explanation + f" | structural={struct_scores.get(cat,0.0):.3f}"

        boost_verdicts(window_result.malware, 'malware')
        boost_verdicts(window_result.rootkit, 'rootkit')
        boost_verdicts(window_result.aimbot, 'aimbot')
        boost_verdicts(window_result.anticheat, 'anticheat')
        if hasattr(window_result, 'virus'):
            boost_verdicts(window_result.virus, 'virus')

        return window_result

    def correlate_offsets(self, scan_result: MalwareScanResult,
                         game: str = None) -> List[Dict[str, Any]]:
        """
        Correlate detected offsets with known game offsets.
        """
        correlations = []
        all_detections = (scan_result.malware + scan_result.rootkit +
                         scan_result.aimbot + scan_result.anticheat)

        if game and game in self.KNOWN_OFFSETS:
            known = self.KNOWN_OFFSETS[game]
            for det in all_detections:
                for typ, offsets in known.items():
                    for known_off in offsets:
                        if abs(det.offset - known_off) < 0x1000:  # Within 4KB
                            correlations.append({
                                'detected_offset': det.offset,
                                'known_offset': known_off,
                                'type': det.type,
                                'game': game,
                                'confidence': det.confidence,
                            })

        return correlations

    @staticmethod
    def summary_text(scan_result: MalwareScanResult) -> str:
        lines = [
            "═" * 60,
            "  MALWARE DETECTOR — SCAN SUMMARY",
            "═" * 60,
            f"  Total windows scanned: {scan_result.total_scanned}",
            "",
            f"  🦠 MALWARE     : {len(scan_result.malware)}",
            f"  🔧 ROOTKIT     : {len(scan_result.rootkit)}",
            f"  🎯 AIMBOT      : {len(scan_result.aimbot)}",
            f"  🛡️  ANTICHEAT  : {len(scan_result.anticheat)}",
            f"  💉 VIRUS       : {len(scan_result.virus) if hasattr(scan_result, 'virus') else 0}",
            f"  ✅ CLEAN       : {scan_result.clean}",
        ]
        if scan_result.errors:
            lines += ["", f"  ⚠  Errors: {len(scan_result.errors)}"]
        lines.append("═" * 60)

        for typ, detections in [('MALWARE', scan_result.malware),
                       ('ROOTKIT', scan_result.rootkit),
                       ('AIMBOT', scan_result.aimbot),
                       ('ANTICHEAT', scan_result.anticheat),
                       ('VIRUS', getattr(scan_result, 'virus', []))]:
            if detections:
                lines.append(f"\n  {typ} DETECTIONS:")
                for d in detections[:10]:
                    lines.append(f"    0x{d.offset:08x}  Conf={d.confidence:.2f}  {d.reason}")

        return "\n".join(lines)
