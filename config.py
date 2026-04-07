"""
E-BOX 512 RE Tool v3.2 — Configuration Manager
Handles settings, defaults, and environment setup
"""

from __future__ import annotations
import os
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Any, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Default Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalysisConfig:
    """Binary analysis settings"""
    window_size: int = 512
    step_size: int = 256
    recurse_extraction: bool = True
    max_embedded_depth: int = 3
    string_min_length: int = 5
    entropy_low_threshold: float = 3.0
    entropy_high_threshold: float = 7.5


@dataclass
class DecompileConfig:
    """Decompilation settings"""
    max_functions: int = 100
    max_instructions: int = 20000
    max_code_size: int = 200 * 1024  # 200 KB
    include_pseudo_c: bool = True
    include_xrefs: bool = True


@dataclass
class MalwareConfig:
    """Malware detection settings"""
    enable_ml: bool = True
    malware_threshold: float = 0.5
    rootkit_threshold: float = 0.4
    aimbot_threshold: float = 0.45
    anticheat_threshold: float = 0.6
    parallel_workers: int = 8


@dataclass
class GPUConfig:
    """GPU acceleration settings"""
    enable_gpu: bool = True
    vram_cap_mb: float = 3500.0  # GTX 850M
    gpu_fallback_to_cpu: bool = True


@dataclass
class GUIConfig:
    """UI/UX settings"""
    theme: str = "dark"  # dark, light
    refresh_interval_ms: int = 100
    window_width: int = 1400
    window_height: int = 900
    auto_save_reports: bool = True
    report_dir: str = "./reports"


@dataclass
class EBoxConfig:
    """Master configuration class"""
    analysis: AnalysisConfig = None
    decompile: DecompileConfig = None
    malware: MalwareConfig = None
    gpu: GPUConfig = None
    gui: GUIConfig = None
    
    def __post_init__(self):
        if self.analysis is None:
            self.analysis = AnalysisConfig()
        if self.decompile is None:
            self.decompile = DecompileConfig()
        if self.malware is None:
            self.malware = MalwareConfig()
        if self.gpu is None:
            self.gpu = GPUConfig()
        if self.gui is None:
            self.gui = GUIConfig()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'analysis': asdict(self.analysis),
            'decompile': asdict(self.decompile),
            'malware': asdict(self.malware),
            'gpu': asdict(self.gpu),
            'gui': asdict(self.gui),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EBoxConfig:
        """Load from dictionary"""
        try:
            config = cls()
            
            if 'analysis' in data:
                config.analysis = AnalysisConfig(**data['analysis'])
            if 'decompile' in data:
                config.decompile = DecompileConfig(**data['decompile'])
            if 'malware' in data:
                config.malware = MalwareConfig(**data['malware'])
            if 'gpu' in data:
                config.gpu = GPUConfig(**data['gpu'])
            if 'gui' in data:
                config.gui = GUIConfig(**data['gui'])
            
            return config
        except Exception as ex:
            print(f"[WARN] Failed to load config: {ex}, using defaults")
            return cls()


# ─────────────────────────────────────────────────────────────────────────────
# Configuration Manager
# ─────────────────────────────────────────────────────────────────────────────

class ConfigManager:
    """Handle loading/saving configuration"""
    
    CONFIG_FILE = "./ebox.json"
    
    @classmethod
    def load(cls) -> EBoxConfig:
        """Load configuration from file or create default"""
        try:
            if os.path.exists(cls.CONFIG_FILE):
                with open(cls.CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    return EBoxConfig.from_dict(data)
        except Exception as ex:
            print(f"[WARN] Could not load config file: {ex}")
        
        # Return defaults
        return EBoxConfig()
    
    @classmethod
    def save(cls, config: EBoxConfig) -> bool:
        """Save configuration to file"""
        try:
            with open(cls.CONFIG_FILE, 'w') as f:
                json.dump(config.to_dict(), f, indent=2)
            return True
        except Exception as ex:
            print(f"[WARN] Could not save config: {ex}")
            return False
    
    @classmethod
    def reset(cls) -> EBoxConfig:
        """Reset to defaults"""
        config = EBoxConfig()
        cls.save(config)
        return config


# ─────────────────────────────────────────────────────────────────────────────
# Environment Detection
# ─────────────────────────────────────────────────────────────────────────────

class EnvironmentDetector:
    """Detect runtime environment capabilities"""
    
    @staticmethod
    def detect_gpu() -> bool:
        """Check if GPU (CuPy) is available"""
        try:
            import cupy as cp
            cp.array([1])
            return True
        except Exception:
            return False
    
    @staticmethod
    def detect_capstone() -> bool:
        """Check if Capstone is available"""
        try:
            import capstone
            return True
        except ImportError:
            return False
    
    @staticmethod
    def detect_elftools() -> bool:
        """Check if pyelftools is available"""
        try:
            from elftools.elf.elffile import ELFFile
            return True
        except ImportError:
            return False
    
    @staticmethod
    def get_report() -> Dict[str, bool]:
        """Get environment capability report"""
        return {
            'gpu_available': EnvironmentDetector.detect_gpu(),
            'capstone_available': EnvironmentDetector.detect_capstone(),
            'elftools_available': EnvironmentDetector.detect_elftools(),
        }
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get system information"""
        import platform
        import os
        
        return {
            'os': platform.system(),
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu_count': os.cpu_count() or 1,
            'python_executable': os.sys.executable,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Main Functions
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Demo configuration manager"""
    print("E-BOX Configuration Manager\n")
    
    # Load config
    config = ConfigManager.load()
    print("✓ Configuration loaded")
    
    # Show environment
    print("\n📊 System Environment:")
    for key, val in EnvironmentDetector.get_system_info().items():
        print(f"  {key:<20}: {val}")
    
    print("\n⚙️  Component Availability:")
    for key, val in EnvironmentDetector.get_report().items():
        status = "✓" if val else "✗"
        print(f"  {status} {key:<25}: {val}")
    
    # Show config
    print("\n📋 Current Configuration:")
    print(f"  Analysis window size : {config.analysis.window_size}")
    print(f"  Max functions        : {config.decompile.max_functions}")
    print(f"  GPU enabled          : {config.gpu.enable_gpu}")
    print(f"  VRAM cap (MB)        : {config.gpu.vram_cap_mb}")
    print(f"  Parallel workers     : {config.malware.parallel_workers}")
    
    print("\n[OK] Configuration ready!")


if __name__ == '__main__':
    main()
