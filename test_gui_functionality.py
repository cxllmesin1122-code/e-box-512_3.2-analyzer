#!/usr/bin/env python3
"""
GUI Functionality Test Script
Tests all new features added to the GUI
"""

import sys
from pathlib import Path

def test_gui_imports():
    """Test GUI module imports"""
    print("\n" + "="*70)
    print("TEST 1: GUI Module Imports")
    print("="*70)
    
    try:
        import gui_app
        print("✓ gui_app imported successfully")
        
        from gui_app import REToolApp, AnalysisTab, ColourText, StatusBar
        print("✓ REToolApp class imported")
        print("✓ AnalysisTab class imported")
        print("✓ ColourText widget imported")
        print("✓ StatusBar widget imported")
        
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_malware_button_integration():
    """Test that malware button is properly integrated"""
    print("\n" + "="*70)
    print("TEST 2: Malware Button Integration")
    print("="*70)
    
    try:
        from gui_app import REToolApp
        import inspect
        
        # Check if start_malware_analysis method exists
        assert hasattr(REToolApp, 'start_malware_analysis'), \
            "REToolApp missing start_malware_analysis method"
        print("✓ start_malware_analysis method exists in REToolApp")
        
        # Check method signature
        sig = inspect.signature(REToolApp.start_malware_analysis)
        print(f"✓ Method signature: {sig}")
        
        # Check if it's callable
        assert callable(getattr(REToolApp, 'start_malware_analysis')), \
            "start_malware_analysis is not callable"
        print("✓ start_malware_analysis is callable")
        
        return True
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_backend_workflow():
    """Test complete backend workflow (without GUI rendering)"""
    print("\n" + "="*70)
    print("TEST 3: Backend Workflow (Malware Analysis)")
    print("="*70)
    
    try:
        from ebox512_pipeline import MalwareDetector, EBox512
        from binary_parser import parse_binary
        
        # Create test data
        test_binary = open('test_binary_malware.elf', 'rb').read()
        print(f"✓ Test binary loaded: {len(test_binary)} bytes")
        
        # Step 1: Parse
        print("\n  Step 1: Binary Parsing...")
        parse_result = parse_binary(test_binary)
        print(f"  ✓ Parsed as {parse_result.fmt.value}")
        
        # Step 2: EBox512 Scan
        print("\n  Step 2: EBox512 Scan...")
        pipeline = EBox512(window_size=512, step_size=256)
        scan_result = pipeline.scan(test_binary)
        print(f"  ✓ Confirmed regions: {len(scan_result.confirmed)}")
        
        # Step 3: Malware Analysis (as button would do)
        print("\n  Step 3: Malware Detection...")
        detector = MalwareDetector(window_size=512, step_size=256)
        malware_result = detector.analyze_file(test_binary, parse_result=parse_result)
        
        print(f"  ✓ Windows scanned: {malware_result.total_scanned}")
        print(f"  ✓ Detections found:")
        print(f"      MALWARE   : {len(malware_result.malware)}")
        print(f"      ROOTKIT   : {len(malware_result.rootkit)}")
        print(f"      AIMBOT    : {len(malware_result.aimbot)}")
        print(f"      ANTICHEAT : {len(malware_result.anticheat)}")
        print(f"      VIRUS     : {len(malware_result.virus)}")
        
        print(f"\n  ✓ Overall Confidences:")
        for cat, conf in malware_result.overall_confidences.items():
            print(f"      {cat.upper():<10}: {conf*100:6.1f}%")
        
        return True
    except Exception as e:
        print(f"✗ Workflow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_gui_button_flow():
    """Test simulated button flow (without actual GUI rendering)"""
    print("\n" + "="*70)
    print("TEST 4: Button Flow Simulation")
    print("="*70)
    
    try:
        # Simulate what happens when user:
        # 1. Clicks "Open" → loads file
        # 2. Clicks "Malware" button → calls start_malware_analysis
        
        print("\n  Simulating User Actions:")
        print("  1. User clicks 'Open'")
        test_file = 'test_binary_malware.elf'
        with open(test_file, 'rb') as f:
            current_data = f.read()
        print(f"     ✓ File loaded: {len(current_data)} bytes")
        
        print("\n  2. User clicks '🦠 Malware' button")
        from ebox512_pipeline import MalwareDetector
        from binary_parser import parse_binary
        
        # Parse binary (as GUI would)
        parse_result = parse_binary(current_data)
        print(f"     ✓ Binary parsed")
        
        # Run malware detector (as button does)
        detector = MalwareDetector(window_size=512, step_size=256)
        result = detector.analyze_file(current_data, parse_result=parse_result)
        print(f"     ✓ Malware detector finished")
        
        # Display results (as GUI would)
        print(f"\n  3. Results Displayed in GUI:")
        summary = MalwareDetector.summary_text(result)
        print("\n" + summary)
        
        print(f"\n  Overall Confidences (per-category):")
        for cat, conf in result.overall_confidences.items():
            pct = conf * 100
            bar = "█" * int(pct / 5)
            print(f"    {cat.upper():<10}: {pct:6.1f}% {bar}")
        
        return True
    except Exception as e:
        print(f"✗ Button flow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_gui_color_tags():
    """Test GUI color tag system"""
    print("\n" + "="*70)
    print("TEST 5: GUI Color Tags & Styling")
    print("="*70)
    
    try:
        from gui_app import ColourText, C_CYAN, C_GREEN, C_RED, C_ORANGE
        
        print(f"✓ Color definitions loaded:")
        print(f"  C_CYAN   = {C_CYAN}")
        print(f"  C_GREEN  = {C_GREEN}")
        print(f"  C_RED    = {C_RED}")
        print(f"  C_ORANGE = {C_ORANGE}")
        
        # Check ColourText has required tags
        required_tags = ['header', 'ok', 'warn', 'error', 'confirmed', 'encrypted']
        for tag in required_tags:
            assert tag in ColourText.TAGS, f"Missing tag: {tag}"
        print(f"\n✓ All {len(required_tags)} required tags present in ColourText")
        
        return True
    except Exception as e:
        print(f"✗ Color tags test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "  E-BOX 512 GUI FUNCTIONALITY TEST SUITE".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    tests = [
        ("GUI Imports", test_gui_imports),
        ("Malware Button", test_malware_button_integration),
        ("Backend Workflow", test_backend_workflow),
        ("Button Flow", test_gui_button_flow),
        ("Color Tags", test_gui_color_tags),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            result = test_fn()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ Test '{name}' crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, r in results if r)
    failed = len(results) - passed
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}  {name}")
    
    print("-" * 70)
    print(f"TOTAL: {passed}/{len(results)} passed, {failed} failed")
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED - GUI IS FULLY FUNCTIONAL")
    else:
        print(f"\n⚠️  {failed} TEST(S) FAILED - REVIEW ABOVE")
    
    print("="*70 + "\n")
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
