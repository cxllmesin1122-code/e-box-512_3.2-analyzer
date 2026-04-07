"""
E-BOX 512 RE Tool v3.2 — Comprehensive Test Suite
Tests all modules for correctness and performance
"""

from __future__ import annotations
import sys
import time
import io
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Test Utilities
# ─────────────────────────────────────────────────────────────────────────────

class TestResult:
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.duration = 0.0
        self.error = None
        self.details = ""
    
    def __str__(self):
        status = "✓ PASS" if self.passed else "✗ FAIL"
        timespan = f"{self.duration*1000:.1f}ms"
        error_msg = f" | {self.error}" if self.error else ""
        return f"  {status:<12} {self.name:<40} {timespan:<10}{error_msg}"


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_imports():
    """Test that all modules can be imported"""
    result = TestResult("Import all modules")
    t0 = time.perf_counter()
    try:
        import binary_parser
        import decompiler_engine
        import ebox512_pipeline
        import medical_unit
        import config
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


def test_binary_parser():
    """Test binary parser entropy calculation"""
    result = TestResult("Binary parser entropy")
    t0 = time.perf_counter()
    try:
        from binary_parser import calc_entropy, detect_format, BinaryFormat
        
        # Test entropy on known patterns
        test_data = b"Hello World! This is a test string for entropy calculation."
        H = calc_entropy(test_data)
        assert 3.0 < H < 6.0, f"Entropy out of range: {H}"
        
        # Test format detection
        elf_magic = b'\x7fELF'
        fmt = detect_format(elf_magic + b'\x00' * 100)
        assert fmt == BinaryFormat.ELF, f"ELF detection failed: {fmt}"
        
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


def test_ebox512_entropy():
    """Test EBox512 entropy calculation"""
    result = TestResult("EBox512 entropy functions")
    t0 = time.perf_counter()
    try:
        from ebox512_pipeline import EBox512
        
        ebox = EBox512()
        
        # Test entropy - use actually random data
        import random
        test_data = bytes(random.randint(0, 255) for _ in range(512))
        H = ebox.entropy(test_data)
        assert 2.0 < H < 8.0, f"Entropy unexpected: {H}"
        
        # Test entropy gradient
        delta_H = ebox.entropy_gradient(5.0, 4.0)
        assert delta_H > 0, f"Delta entropy should be positive: {delta_H}"
        
        # Test chi2
        chi2 = ebox.chi2_score(test_data)
        assert 0.0 <= chi2 <= 1.0, f"Chi2 out of range: {chi2}"
        
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


def test_medical_unit():
    """Test MedicalUnit error tracking"""
    result = TestResult("Medical unit error tracking")
    t0 = time.perf_counter()
    try:
        from medical_unit import MedicalUnit, Severity
        
        mu = MedicalUnit()
        
        # Test successful operation
        def success_fn():
            return "OK"
        
        ok, res, err = mu.guard("test_module", success_fn)
        assert ok, f"Guard failed: {err}"
        assert res == "OK", f"Result mismatch: {res}"
        
        # Test failed operation (MemoryError skipped for safety)
        def fail_fn():
            raise ValueError("Test error")
        
        ok, res, err = mu.guard("test_module", fail_fn)
        assert not ok, "Guard should fail"
        assert "ValueError" in err, f"Error message mismatch: {err}"
        
        # Check health
        assert not mu.is_healthy(), "Should detect error"
        
        # Check module health
        health = mu.module_health
        assert "test_module" in health, "Module not registered"
        
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


def test_config_manager():
    """Test configuration management"""
    result = TestResult("Configuration manager")
    t0 = time.perf_counter()
    try:
        from config import ConfigManager, EBoxConfig
        
        # Load defaults
        config = ConfigManager.load()
        assert config.analysis.window_size > 0, "Config not loaded"
        
        # Check environment
        from config import EnvironmentDetector
        env_report = EnvironmentDetector.get_report()
        assert isinstance(env_report, dict), "Environment report failed"
        
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


def test_decompiler_engines():
    """Test decompiler architecture detection"""
    result = TestResult("Decompiler arch detection")
    t0 = time.perf_counter()
    try:
        from decompiler_engine import detect_arch_elf
        
        # ELF x86_64
        elf_x86_64 = b'\x7fELF\x02\x01\x01' + b'\x00' * 11 + b'\x3e\x00' + b'\x00' * 100
        arch = detect_arch_elf(elf_x86_64 + b'\x00' * 10)
        assert arch == 'x86_64', f"Arch detection failed: {arch}"
        
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


def test_malware_detector():
    """Test malware detection basics"""
    result = TestResult("Malware detector initialization")
    t0 = time.perf_counter()
    try:
        from ebox512_pipeline import MalwareDetector
        
        detector = MalwareDetector(window_size=512, step_size=256)
        
        # Test signature matching
        test_data = bytes(range(256)) * 2
        verdict = detector.detect_window(test_data, offset=0)
        
        assert verdict is not None, "Verdict is None"
        assert hasattr(verdict, 'confidence'), "Verdict missing confidence"
        assert 0.0 <= verdict.confidence <= 1.0, f"Confidence out of range: {verdict.confidence}"
        # New fields: per-category scores and operational probability
        assert hasattr(verdict, 'scores'), "Verdict missing scores dict"
        assert isinstance(verdict.scores, dict), "scores should be a dict"
        assert hasattr(verdict, 'operational_prob'), "Verdict missing operational_prob"
        assert 0.0 <= verdict.operational_prob <= 1.0, f"Operational prob out of range: {verdict.operational_prob}"

        # High-level file analysis
        file_result = detector.analyze_file(test_data)
        assert hasattr(file_result, 'overall_confidences'), "Missing overall_confidences"
        assert isinstance(file_result.overall_confidences, dict), "overall_confidences must be a dict"
        for v in file_result.overall_confidences.values():
            assert 0.0 <= v <= 1.0, f"Overall confidence out of range: {v}"
        
        result.passed = True
    except Exception as ex:
        result.error = str(ex)
    finally:
        result.duration = time.perf_counter() - t0
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Test Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_all_tests():
    """Execute all tests and report results"""
    print("\n" + "═" * 80)
    print("  E-BOX 512 RE Tool v3.2 — Comprehensive Test Suite")
    print("═" * 80 + "\n")
    
    tests = [
        test_imports,
        test_binary_parser,
        test_ebox512_entropy,
        test_medical_unit,
        test_config_manager,
        test_decompiler_engines,
        test_malware_detector,
    ]
    
    results = []
    passed = 0
    failed = 0
    total_duration = 0.0
    
    for test_fn in tests:
        result = test_fn()
        results.append(result)
        
        if result.passed:
            passed += 1
        else:
            failed += 1
        
        total_duration += result.duration
        print(result)
    
    # Summary
    print("\n" + "─" * 80)
    print(f"  SUMMARY: {passed}/{len(results)} passed, {failed} failed")
    print(f"  Total time: {total_duration*1000:.1f}ms")
    print("═" * 80 + "\n")
    
    return failed == 0


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
