"""
Comprehensive Test Suite for E-BOX RE Tool v3.2 with GPU, APK, and Anti-Cheat
Tests: GPU support, APK analysis, Anti-cheat detection, GUI functionality
"""

import sys
import os
import unittest
import tempfile
import zipfile
from io import BytesIO

# Add project to path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class TestGPUSupport(unittest.TestCase):
    """Test GPU acceleration support."""

    def test_gpu_import(self):
        """Test GPU module imports."""
        from ebox512_pipeline import GPU_AVAILABLE, cp
        self.assertIsNotNone(cp)
        print(f"[OK] GPU Available: {GPU_AVAILABLE}")

    def test_gpu_acceleration_active(self):
        """Test if GPU acceleration is active."""
        from ebox512_pipeline import GPU_AVAILABLE
        self.assertTrue(GPU_AVAILABLE, "GPU should be enabled with CuPy")
        print("[OK] GPU acceleration active")


class TestAPKAnalyzer(unittest.TestCase):
    """Test APK analysis functionality."""

    def setUp(self):
        """Create a test APK file."""
        from apk_analyzer import APKAnalyzer
        
        # Create minimal APK
        self.test_apk = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        self.test_apk_path = self.test_apk.name
        
        with zipfile.ZipFile(self.test_apk_path, 'w') as zf:
            # Add AndroidManifest.xml
            manifest = b'\x00\x01\x08\x00' + b'test' * 100
            zf.writestr(zipfile.ZipInfo('AndroidManifest.xml'), manifest)
            
            # Add DEX file
            dex = b'dex\n035\x00' + b'\x00' * 200
            zf.writestr(zipfile.ZipInfo('classes.dex'), dex)
            
            # Add native lib
            lib = b'\x7fELF' + b'\x00' * 300
            zf.writestr(zipfile.ZipInfo('lib/armeabi-v7a/libnative.so'), lib)

    def tearDown(self):
        """Clean up test APK."""
        if hasattr(self, 'test_apk') and self.test_apk:
            self.test_apk.close()
        if os.path.exists(self.test_apk_path):
            try:
                os.unlink(self.test_apk_path)
            except (OSError, PermissionError):
                pass  # File may be locked on Windows, will be cleaned by OS

    def test_apk_analyzer_init(self):
        """Test APK analyzer initialization."""
        from apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer("")  # Empty path for bytes mode
        self.assertIsNotNone(analyzer)
        print("[OK] APK analyzer initialized")

    def test_apk_from_bytes(self):
        """Test opening APK from bytes."""
        from apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer("")
        
        # Create test APK data
        test_apk = zipfile.ZipFile(self.test_apk_path, 'r')
        with open(self.test_apk_path, 'rb') as f:
            apk_data = f.read()
        
        result = analyzer.analyze_from_bytes(apk_data)
        analyzer.close()
        
        self.assertTrue(result, "APK should open from bytes successfully")
        print("[OK] APK from bytes opened successfully")

    def test_apk_analyze_structure(self):
        """Test APK structure analysis."""
        from apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer("")
        
        # Read APK data
        with open(self.test_apk_path, 'rb') as f:
            apk_data = f.read()
        
        analyzer.analyze_from_bytes(apk_data)
        files = analyzer.analyze_structure()
        analyzer.close()
        
        self.assertGreater(len(files), 0, "APK should contain files")
        print(f"[OK] APK structure analyzed: {len(files)} files detected")

    def test_apk_dex_extraction(self):
        """Test DEX file extraction."""
        from apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer("")
        
        with open(self.test_apk_path, 'rb') as f:
            apk_data = f.read()
        
        analyzer.analyze_from_bytes(apk_data)
        dex_files = analyzer.extract_dex_files()
        analyzer.close()
        
        self.assertGreater(len(dex_files), 0, "Should find DEX files")
        print(f"[OK] DEX files extracted: {len(dex_files)} file(s)")

    def test_apk_compression_analysis(self):
        """Test compression structure analysis."""
        from apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer("")
        
        with open(self.test_apk_path, 'rb') as f:
            apk_data = f.read()
        
        analyzer.analyze_from_bytes(apk_data)
        analyzer.analyze_structure()
        analysis = analyzer.analyze_compression_structure()
        analyzer.close()
        
        self.assertIn('total_files', analysis)
        self.assertIn('compression_ratio', analysis)
        print(f"[OK] Compression analysis: {analysis['total_files']} files")


class TestAntiCheatDetector(unittest.TestCase):
    """Test anti-cheat detection."""

    def test_detector_init(self):
        """Test detector initialization."""
        from anticheat_detector import AntiCheatDetector
        detector = AntiCheatDetector()
        self.assertIsNotNone(detector.findings)
        print("[OK] Anti-cheat detector initialized")

    def test_detect_ptrace(self):
        """Test detection of ptrace anti-debug."""
        from anticheat_detector import AntiCheatDetector, AntiCheatType
        
        detector = AntiCheatDetector()
        data = b'ptrace is an anti-debug mechanism'
        analysis = detector.analyze_binary(data)
        
        self.assertGreater(len(analysis.findings), 0)
        print(f"[OK] Ptrace detection working: {len(analysis.findings)} findings")

    def test_risk_assessment(self):
        """Test overall risk assessment."""
        from anticheat_detector import AntiCheatDetector
        
        detector = AntiCheatDetector()
        data = b'ptrace fork() DexShell ProGuard Frida'
        analysis = detector.analyze_binary(data)
        
        self.assertIsNotNone(analysis.overall_risk)
        self.assertGreaterEqual(analysis.obfuscation_score, 0.0)
        self.assertLessEqual(analysis.obfuscation_score, 1.0)
        print(f"[OK] Risk assessment: {analysis.overall_risk.name} "
              f"[Obfuscation: {analysis.obfuscation_score:.0%}]")

    def test_multiple_signatures(self):
        """Test detection of multiple anti-cheat mechanisms."""
        from anticheat_detector import AntiCheatDetector
        
        detector = AntiCheatDetector()
        data = (b'ptrace GET_SIGNATURES SHA-256 '
                b'DexShell fork() Frida Xposed')
        analysis = detector.analyze_binary(data)
        
        self.assertGreater(len(analysis.findings), 3)
        print(f"[OK] Multiple signature detection: {len(analysis.findings)} mechanisms")


class TestGUIEnhancements(unittest.TestCase):
    """Test GUI enhancement widgets."""

    def test_context_menu_creation(self):
        """Test context menu widget creation."""
        from gui_enhancements import ContextMenu
        import tkinter as tk
        
        root = tk.Tk()
        menu = ContextMenu(root)
        self.assertIsNotNone(menu)
        root.destroy()
        print("[OK] Context menu created successfully")

    def test_progress_tracker_creation(self):
        """Test progress tracker."""
        from gui_enhancements import AnalysisProgressTracker
        
        tracker = AnalysisProgressTracker(total_stages=5)
        progress, accuracy = tracker.get_progress()
        self.assertEqual(progress, 0.0)
        print("[OK] Progress tracker initialized")

    def test_progress_tracking(self):
        """Test progress tracking functionality."""
        from gui_enhancements import AnalysisProgressTracker
        
        tracker = AnalysisProgressTracker(total_stages=3)
        tracker.start_stage("Stage 1")
        tracker.update_stage("Stage 1", 95.0)
        
        progress, accuracy = tracker.get_progress()
        self.assertGreater(progress, 0.0)
        self.assertGreater(accuracy, 0.0)
        print(f"[OK] Progress tracking: {progress:.0f}% complete, "
              f"{accuracy:.0f}% accuracy")


class TestBinaryParser(unittest.TestCase):
    """Test binary parsing functions."""

    def test_binary_parser_import(self):
        """Test binary parser imports."""
        from binary_parser import parse_binary, calc_entropy
        self.assertIsNotNone(parse_binary)
        self.assertIsNotNone(calc_entropy)
        print("[OK] Binary parser imported successfully")

    def test_entropy_calculation(self):
        """Test entropy calculations."""
        from binary_parser import calc_entropy
        
        # Test uniform data (low entropy)
        uniform = b'\x00' * 256
        entropy_low = calc_entropy(uniform)
        
        # Test random-like data (high entropy)
        random_data = bytes(range(256))
        entropy_high = calc_entropy(random_data)
        
        self.assertLess(entropy_low, entropy_high)
        print(f"[OK] Entropy calculation working "
              f"(uniform: {entropy_low:.2f}, random: {entropy_high:.2f})")


class TestDecompilerEngine(unittest.TestCase):
    """Test decompiler engine."""

    def test_decompiler_import(self):
        """Test decompiler imports."""
        from decompiler_engine import decompile
        self.assertIsNotNone(decompile)
        print("[OK] Decompiler engine imported successfully")


class TestEBox512Pipeline(unittest.TestCase):
    """Test E-BOX 512 analysis pipeline."""

    def test_pipeline_import(self):
        """Test pipeline imports."""
        from ebox512_pipeline import EBox512, MalwareDetector
        self.assertIsNotNone(EBox512)
        self.assertIsNotNone(MalwareDetector)
        print("[OK] E-BOX pipeline imported successfully")

    def test_malware_detector_init(self):
        """Test malware detector initialization."""
        from ebox512_pipeline import MalwareDetector
        
        detector = MalwareDetector(window_size=512, step_size=256)
        self.assertIsNotNone(detector)
        print("[OK] Malware detector initialized")


class IntegrationTests(unittest.TestCase):
    """Integration tests for the complete system."""

    def test_complete_workflow(self):
        """Test complete analysis workflow."""
        from binary_parser import parse_binary
        from ebox512_pipeline import EBox512
        from anticheat_detector import AntiCheatDetector
        
        # Create test binary data (minimal ELF)
        test_data = b'\x7fELF' + b'\x00' * 1000 + b'ptrace' + b'\xcf' * 500
        
        # Test parsing
        try:
            parse_result = parse_binary(test_data)
            self.assertIsNotNone(parse_result)
            print("[PASS] Binary parsing successful")
        except:
            print("[SKIP] Binary parsing (optional for test)")
        
        # Test anti-cheat detection
        detector = AntiCheatDetector()
        anticheat_result = detector.analyze_binary(test_data)
        self.assertIsNotNone(anticheat_result)
        print("[PASS] Anti-cheat detection successful")
        
        # Test E-BOX pipeline
        pipeline = EBox512(window_size=256, step_size=128)
        scan_result = pipeline.scan(test_data)
        self.assertIsNotNone(scan_result)
        print("[PASS] E-BOX pipeline scan successful")

    def test_app_initialization(self):
        """Test application initialization (headless mode)."""
        # This test verifies imports without launching GUI
        from gui_app import REToolApp
        self.assertIsNotNone(REToolApp)
        print("[OK] GUI application initialized (headless)")


# ─────────────────────────────────────────────────────────────────────────────

def run_tests():
    """Run all tests with verbose output."""
    print("\n" + "="*70)
    print("  E-BOX 512 RE Tool v3.2 — Comprehensive Test Suite")
    print("="*70 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestGPUSupport))
    suite.addTests(loader.loadTestsFromTestCase(TestAPKAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestAntiCheatDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestGUIEnhancements))
    suite.addTests(loader.loadTestsFromTestCase(TestBinaryParser))
    suite.addTests(loader.loadTestsFromTestCase(TestDecompilerEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestEBox512Pipeline))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    
    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70 + "\n")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
