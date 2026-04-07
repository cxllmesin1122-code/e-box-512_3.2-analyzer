"""
Anti-Cheat Detection Engine
Detects common anti-debugging, anti-tamper, and DRM mechanisms
Analyzes: Code obfuscation · Integrity checks · Debugging prevention · Encryption
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Tuple
from enum import Enum
import re
from binary_parser import parse_binary


class AntiCheatType(Enum):
    """Types of anti-cheat mechanisms."""
    ANTI_DEBUG = "Anti-Debugging"
    ANTI_TAMPER = "Anti-Tampering"
    OBFUSCATION = "Code Obfuscation"
    INTEGRITY_CHECK = "Integrity Check"
    ENCRYPTION = "Encryption/Encoding"
    ANTI_INSTRUMENTATION = "Anti-Instrumentation"
    DRM = "Digital Rights Management"
    ANTI_EMULATION = "Anti-Emulation"


class RiskLevel(Enum):
    """Risk assessment levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ─────────────────────────────────────────────────────────────────────────────
#  Detection Patterns
# ─────────────────────────────────────────────────────────────────────────────

ANTI_CHEAT_SIGNATURES = {
    # Anti-Debugging
    "Anti-Debug: ptrace": {
        "patterns": [b"ptrace", b"PTRACE_TRACEME"],
        "type": AntiCheatType.ANTI_DEBUG,
        "risk": RiskLevel.HIGH,
        "description": "ptrace syscall - prevents debugger attachment"
    },
    
    "Anti-Debug: /proc/self/status": {
        "patterns": [b"/proc/self/status", b"TracerPid"],
        "type": AntiCheatType.ANTI_DEBUG,
        "risk": RiskLevel.HIGH,
        "description": "Checks /proc/self/status for TracerPid",
    },
    
    "Anti-Debug: fork check": {
        "patterns": [b"fork()", b"vfork()", b"clone()"],
        "type": AntiCheatType.ANTI_DEBUG,
        "risk": RiskLevel.MEDIUM,
        "description": "Uses fork/vfork to detect debugger",
    },
    
    # Anti-Tampering
    "Anti-Tamper: APK signature check": {
        "patterns": [b"GET_SIGNATURES", b"checkSignatures", b"verifyAPK"],
        "type": AntiCheatType.ANTI_TAMPER,
        "risk": RiskLevel.MEDIUM,
        "description": "Verifies APK signing certificate",
    },
    
    "Anti-Tamper: File integrity": {
        "patterns": [b"MessageDigest", b"SHA-256", b"CRC32"],
        "type": AntiCheatType.ANTI_TAMPER,
        "risk": RiskLevel.MEDIUM,
        "description": "Checks file integrity with hash",
    },
    
    "Anti-Tamper: DEX protection": {
        "patterns": [b"dexClassLoader", b"DexShell"],
        "type": AntiCheatType.ANTI_TAMPER,
        "risk": RiskLevel.HIGH,
        "description": "Dynamic DEX loading/protection",
    },
    
    # Obfuscation
    "Obfuscation: ProGuard": {
        "patterns": [b"ProGuard", b"yWVsbG8gV29ybGQ="],  # base64 "Hello World"
        "type": AntiCheatType.OBFUSCATION,
        "risk": RiskLevel.MEDIUM,
        "description": "Code obfuscated with ProGuard",
    },
    
    "Obfuscation: Reflection": {
        "patterns": [b"forName", b"getMethod", b"invoke"],
        "type": AntiCheatType.OBFUSCATION,
        "risk": RiskLevel.MEDIUM,
        "description": "Heavy use of Java reflection",
    },
    
    "Obfuscation: String encryption": {
        "patterns": [b"XOREncrypt", b"AES", b"RSA"],
        "type": AntiCheatType.ENCRYPTION,
        "risk": RiskLevel.MEDIUM,
        "description": "Strings encrypted or encoded",
    },
    
    # Anti-Instrumentation
    "Anti-Instrumentation: Frida": {
        "patterns": [b"frida", b"gadget.so"],
        "type": AntiCheatType.ANTI_INSTRUMENTATION,
        "risk": RiskLevel.CRITICAL,
        "description": "Detects Frida instrumentation",
    },
    
    "Anti-Instrumentation: Xposed": {
        "patterns": [b"XposedBridge", b"xposed"],
        "type": AntiCheatType.ANTI_INSTRUMENTATION,
        "risk": RiskLevel.HIGH,
        "description": "Detects Xposed hooks",
    },
    
    # DRM
    "DRM: Google Play Protect": {
        "patterns": [b"Google Play Protect", b"isLicenseValid"],
        "type": AntiCheatType.DRM,
        "risk": RiskLevel.MEDIUM,
        "description": "License verification with Google Play",
    },
    
    # Anti-Emulation
    "Anti-Emulation: Emulator detection": {
        "patterns": [b"ro.kernel.qemu", b"ro.build.fingerprint"],
        "type": AntiCheatType.ANTI_EMULATION,
        "risk": RiskLevel.MEDIUM,
        "description": "Detects emulator through system properties",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  Detection Results
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AntiCheatFinding:
    """Single anti-cheat detection result."""
    name: str
    type: AntiCheatType
    risk_level: RiskLevel
    description: str
    location: str = ""
    confidence: float = 0.0  # 0.0 - 1.0
    
    def __str__(self) -> str:
        risk_str = f"[{self.risk_level.name}]"
        return f"{risk_str} {self.name}: {self.description}"


@dataclass
class AntiCheatAnalysis:
    """Complete anti-cheat analysis report."""
    findings: List[AntiCheatFinding]
    overall_risk: RiskLevel
    obfuscation_score: float  # 0.0 - 1.0
    anti_debug_detected: bool
    anti_tamper_detected: bool
    drm_detected: bool
    
    def __str__(self) -> str:
        lines = [f"Anti-Cheat Analysis Report"]
        lines.append(f"Overall Risk: {self.overall_risk.name}")
        lines.append(f"Obfuscation Score: {self.obfuscation_score:.0%}")
        lines.append(f"\nDetections ({len(self.findings)}):")
        
        for finding in self.findings:
            lines.append(f"  • {finding}")
        
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Detector Engine
# ─────────────────────────────────────────────────────────────────────────────

class AntiCheatDetector:
    """Detects anti-cheat and protection mechanisms."""
    
    def __init__(self):
        self.findings: List[AntiCheatFinding] = []
    
    def analyze_binary(self, data: bytes) -> AntiCheatAnalysis:
        """Analyze binary data for anti-cheat signatures."""
        self.findings.clear()
        
        def scan_signature(sig_name: str, sig_data: dict, data_blob: bytes, location: str):
            for pattern in sig_data["patterns"]:
                if pattern in data_blob:
                    self.findings.append(AntiCheatFinding(
                        name=sig_name,
                        type=sig_data['type'],
                        risk_level=sig_data['risk'],
                        description=sig_data['description'],
                        location=location,
                        confidence=0.95 if len(pattern) > 6 else 0.70
                    ))
                    return True
            return False

        # Scan raw bytes
        for sig_name, sig_data in ANTI_CHEAT_SIGNATURES.items():
            scan_signature(sig_name, sig_data, data, "root")

        # Parse data for strings and symbols
        try:
            pr = parse_binary(data)
        except Exception:
            pr = None

        if pr:
            all_strings = pr.strings[:]
            if getattr(pr, 'deobfuscated_strings', None):
                all_strings += pr.deobfuscated_strings
            if all_strings:
                all_strings = list(dict.fromkeys(all_strings))

            for sig_name, sig_data in ANTI_CHEAT_SIGNATURES.items():
                patterns = sig_data['patterns']
                for pattern in patterns:
                    try:
                        pat_str = pattern.decode('utf-8', errors='ignore')
                    except Exception:
                        pat_str = ''

                    if pat_str:
                        for s in all_strings:
                            if pat_str in s:
                                self.findings.append(AntiCheatFinding(
                                    name=sig_name,
                                    type=sig_data['type'],
                                    risk_level=sig_data['risk'],
                                    description=sig_data['description'],
                                    location='strings',
                                    confidence=0.80
                                ))
                                break

                    if pr.symbols:
                        for sym in pr.symbols:
                            if pat_str and pat_str in sym.name:
                                self.findings.append(AntiCheatFinding(
                                    name=sig_name,
                                    type=sig_data['type'],
                                    risk_level=sig_data['risk'],
                                    description=sig_data['description'],
                                    location=f"symbol:{sym.name}",
                                    confidence=0.90
                                ))
                                break

        return self._compile_analysis()
    
    def analyze_apk(self, apk_files: Dict[str, bytes]) -> AntiCheatAnalysis:
        """Analyze APK files for anti-cheat mechanisms."""
        self.findings.clear()
        
        def scan_piece(data: bytes, filename: str):
            # Binary-level detection without wiping previous findings
            for sig_name, sig_data in ANTI_CHEAT_SIGNATURES.items():
                patterns = sig_data["patterns"]
                for pattern in patterns:
                    if pattern in data:
                        finding = AntiCheatFinding(
                            name=sig_name,
                            type=sig_data['type'],
                            risk_level=sig_data['risk'],
                            description=sig_data['description'],
                            location=filename,
                            confidence=0.95 if len(pattern) > 6 else 0.70
                        )
                        self.findings.append(finding)
                        break

        for filename, data in apk_files.items():
            scan_piece(data, filename)

            try:
                pr = parse_binary(data)
            except Exception:
                pr = None

            if not pr:
                continue

            patterns_seen = set()
            all_strings = pr.strings[:]
            if getattr(pr, 'deobfuscated_strings', None):
                all_strings += pr.deobfuscated_strings
            if all_strings:
                all_strings = list(dict.fromkeys(all_strings))

            for sig_name, sig_data in ANTI_CHEAT_SIGNATURES.items():
                if sig_name in patterns_seen:
                    continue
                patterns = sig_data['patterns']
                for pattern in patterns:
                    try:
                        pat_str = pattern.decode('utf-8', errors='ignore')
                    except Exception:
                        pat_str = ''

                    if pat_str:
                        for s in all_strings:
                            if pat_str in s:
                                self.findings.append(AntiCheatFinding(
                                    name=sig_name,
                                    type=sig_data['type'],
                                    risk_level=sig_data['risk'],
                                    description=sig_data['description'],
                                    location=filename,
                                    confidence=0.80
                                ))
                                patterns_seen.add(sig_name)
                                break
                        if sig_name in patterns_seen:
                            break

                    if pr.symbols:
                        for sym in pr.symbols:
                            if pat_str and pat_str in sym.name:
                                self.findings.append(AntiCheatFinding(
                                    name=sig_name,
                                    type=sig_data['type'],
                                    risk_level=sig_data['risk'],
                                    description=sig_data['description'],
                                    location=f"{filename}:{sym.name}",
                                    confidence=0.90
                                ))
                                patterns_seen.add(sig_name)
                                break
                        if sig_name in patterns_seen:
                            break

        return self._compile_analysis()
    
    def _compile_analysis(self) -> AntiCheatAnalysis:
        """Compile findings into analysis report."""
        if not self.findings:
            return AntiCheatAnalysis(
                findings=[],
                overall_risk=RiskLevel.NONE,
                obfuscation_score=0.0,
                anti_debug_detected=False,
                anti_tamper_detected=False,
                drm_detected=False
            )
        
        # Group by type
        by_type = {}
        max_risk = RiskLevel.NONE
        
        for finding in self.findings:
            ft = finding.type.name
            if ft not in by_type:
                by_type[ft] = 0
            by_type[ft] += 1
            
            if finding.risk_level.value > max_risk.value:
                max_risk = finding.risk_level
        
        # Calculate obfuscation score
        obf_count = sum(1 for f in self.findings if f.type == AntiCheatType.OBFUSCATION)
        obf_score = min(1.0, obf_count / 5.0)
        
        analysis = AntiCheatAnalysis(
            findings=sorted(self.findings, key=lambda f: f.risk_level.value, reverse=True),
            overall_risk=max_risk,
            obfuscation_score=obf_score,
            anti_debug_detected=any(f.type == AntiCheatType.ANTI_DEBUG for f in self.findings),
            anti_tamper_detected=any(f.type == AntiCheatType.ANTI_TAMPER for f in self.findings),
            drm_detected=any(f.type == AntiCheatType.DRM for f in self.findings)
        )
        
        return analysis
    
    @staticmethod
    def risk_color(risk_level: RiskLevel) -> str:
        """Get color code for risk level (for UI)."""
        colors = {
            RiskLevel.NONE: "#3fb950",      # Green
            RiskLevel.LOW: "#58a6ff",       # Cyan
            RiskLevel.MEDIUM: "#f0883e",   # Orange
            RiskLevel.HIGH: "#f85149",      # Red
            RiskLevel.CRITICAL: "#ff0000"  # Bright red
        }
        return colors.get(risk_level, "#e6edf3")
