# E-BOX 512 RE Tool v3.2 — Complete Guide

## 🎯 Features Overview

### ✅ New Features Added

**1. APK Analysis (📦 APK Analysis Tab)**
- Complete APK structure inspection
- DEX file extraction and analysis
- Native library detection  
- Compression structure analysis
- File-by-file entropy calculation
- Comprehensive metadata display

**2. Anti-Cheat Detection (🛡️ Anti-Cheat Tab)**
- Detects 20+ anti-debugging mechanisms
- Anti-tampering protection detection
- Code obfuscation analysis
- DRM/License verification detection
- Risk assessment (Critical, High, Medium, Low, None)
- Obfuscation score calculation
- Detailed finding reports

**3. GPU Acceleration**
- NVIDIA GPU support via  CuPy
- Automatic fallback to NumPy if GPU unavailable
- GTX 850M optimized (works with other GPUs)
- Significantly faster binary analysis

**4. Enhanced GUI**
- **Right-Click Context Menus**: All text areas support:
  - Copy selected text
  - Copy all content
  - Select all text
- **Progress Tracking**: Real-time progress with accuracy percentage
- **Multiple Tabs**: 7 specialized analysis tabs
- **Copy-to-Clipboard**: Easy result export

**5. Comprehensive Analysis**
- Binary structure analysis (ELF, PE, Mach-O, etc.)
- Entropy analysis and anomaly detection
- Disassembly with pseudo-C generation
- E-BOX 512 malware detection
- Medical unit health assessment
- Comprehensive reporting

---

## 🚀 Quick Start

### Requirements
```bash
Python 3.10+
NVIDIA GPU with CUDA support (optional, will fall back to NumPy)
```

### Installation
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. For GPU support (NVIDIA)
pip install cupy-cuda11x

# 3. Run the application
python gui_app.py
```

### Activation
```bash
# Activate virtual environment (if using venv)
.\.venv\Scripts\Activate.ps1

# Run GUI
python gui_app.py
```

---

## 📖 Usage Guide

### Tab 1: 🔬 Analysis
- **Open**: Load binary file (supports .apk, .elf, .exe, .dll, etc.)
- **Scan**: Run E-BOX 512 analysis pipeline
- **🦠 Malware**: Detect malware patterns
- **Configure**: Set analysis window size (256-2048)

### Tab 2: 📋 Structure
- View binary sections and their properties
- Inspect imports, symbols, and dependencies
- Analyze section entropy and compression
- Right-click for copy functionality

### Tab 3: ⚙ Disasm / C
- View disassembled code at offsets
- Generate pseudo-C code
- Analyze functions and strings
- Real-time decompilation

### Tab 4: 📦 APK Analysis
1. Click "Open APK" to load an Android APK file
2. Click "Analyze" to scan structure
3. View:
   - **📋 Metadata**: Package info, version, permissions, activities
   - **📊 Compression**: File type breakdown, entropy analysis
   - **📁 Summary**: Overall APK information
4. Right-click file tree for detailed inspection

**APK Insights:**
- Detects DEX files and native libraries (.so)
- Analyzes compression ratios
- Identifies high-entropy (encrypted) files
- Shows file type distribution

### Tab 5: 🛡️ Anti-Cheat Analysis
1. Open any binary file (ELF, DEX, native lib, etc.)
2. Click "Analyze" to scan for protection mechanisms
3. View findings categorized by:
   - **Anti-Debugging**: ptrace detection, fork checks, TracerPid
   - **Anti-Tampering**: APK signature verification, DEX protection
   - **Obfuscation**: ProGuard, reflection-heavy code, string encryption
   - **DRM**: License verification, code signing
   - **Anti-Instrumentation**: Frida detection, Xposed hooks
   
4. **Risk Assessment**:
   - Overall risk level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
   - Obfuscation score (0-100%)
   - Detection confidence for each finding

### Tab 6: 🏥 Medical
- System health assessment
- Detection correlation and pattern analysis
- Health timeline visualization

### Tab 7: 📝 Report
- Comprehensive analysis report
- Export scan results
- Statistical breakdown

---

## 🎮 Keyboard & Mouse

### Right-Click Context Menu
```
Any text area (read-only or editable):
  Right-click → Copy         (copy selection)
  Right-click → Copy All     (copy entire text)
  Right-click → Select All   (select all text)
```

### Copy-to-Clipboard
```
All analysis results support:
  - Click to select text
  - Right-click to copy
  - Ctrl+A to select all
  - Automatic clipboard export
```

---

## 📊 Analysis Modes

### E-BOX 512 Pipeline
```
Input Binary → Parse Structure → Calculate Metrics → 
Detect Patterns → Medical Assessment → Report
```

### APK Analysis
```
APK File → Extract Files → Analyze Compression → 
Extract Features → Native Library Check → Report
```

### Anti-Cheat Detection
```
Binary Data → Scan Signatures → Risk Assessment → 
Obfuscation Analysis → Generate Report
```

---

## 🎯 Advanced Usage

### GPU Performance
GPU acceleration is automatically enabled if NVIDIA GPU available:
```
Status Bar shows: ✓ GPU acceleration ENABLED
Falls back to NumPy if GPU unavailable
```

### Window Size & Step Size Configuration
```
⚙ Analysis Tab settings:
  Window: 256, 512, 1024, 2048 bytes
  Step: 128, 256, 512 bytes
  
Larger window = more accurate, slower
Smaller step = more precise, slower
```

### Progress Tracking
```
All long-running analyses show:
  - Real-time progress bar (0-100%)
  - Current accuracy percentage
  - Operation status message
```

---

## 🧪 Testing

Run the comprehensive test suite:
```bash
python comprehensive_test_suite.py
```

Expected output:
```
Ran 21 tests in ~3s
Tests covering:
  ✓ GPU acceleration
  ✓ APK analysis
  ✓ Anti-cheat detection
  ✓ Binary parsing
  ✓ Decompiler engine
  ✓ GUI enhancements
  ✓ Integration workflows
```

---

## 📁 File Structure

```
E-BOX RE Tool/
├── gui_app.py                    # Main GUI application
├── ebox512_pipeline.py           # E-BOX analysis engine (GPU-accelerated)
├── binary_parser.py              # Binary format parsing
├── decompiler_engine.py          # Disassembly & pseudo-C generation
├── apk_analyzer.py               # APK structure analysis
├── apk_gui_tab.py               # APK analysis UI tab
├── anticheat_detector.py        # Anti-cheat signature detection
├── anticheat_gui_tab.py         # Anti-cheat analysis UI tab
├── gui_enhancements.py          # Context menus, copy, progress
├── medical_unit.py              # Health assessment system
├── comprehensive_test_suite.py  # Full test suite (21 tests)
└── requirements.txt             # Python dependencies
```

---

## 🔧 Configuration

### Performance Tuning
```python
# In gui_app.py, AnalysisTab:
Window:   512 bytes (good balance)
Step:     256 bytes (good precision)
```

### GPU Settings
```python
# GPU is automatically enabled in ebox512_pipeline.py
# Falls back to NumPy if unavailable
# No manual configuration needed
```

---

## 📋 Detection Signatures

### Anti-Debug (Examples)
- `ptrace()` calls
- `/proc/self/status` (TracerPid check)
- `fork()`/`vfork()` based detection

### Anti-Tamper (Examples)
- APK signature verification
- DEX file protection (DexShell)
- CRC/SHA-256 integrity checks

### Obfuscation (Examples)
- ProGuard obfuscation
- Heavy reflection usage
- String encryption/XOR

### DRM (Examples)
- Google Play Protect
- License verification
- Code signing checks

### Anti-Instrumentation (Examples)
- Frida detection
- Xposed framework hooks

---

## 🐛 Troubleshooting

### GPU Not Available
```
[GPU] CuPy not available, falling back to NumPy
→ GPU support not installed
→ Run: pip install cupy-cuda11x
→ Or: pip install cupy-cuda12x (for newer CUDA)
```

### APK Analysis Shows No Files
```
→ Verify APK file is valid
→ Try opening with standard zip utility first
→ Check file permissions
```

### Anti-Cheat Detection No Findings
```
→ Binary may not have protection
→ Small or encrypted binaries may not match signatures
→ This is normal for some applications
```

---

## 📈 Performance

### Typical Analysis Times
- **Small binary (< 100 KB)**: 0.5-2 seconds
- **Medium binary (100 KB - 5 MB)**: 2-10 seconds
- **Large binary (> 5 MB)**: 10-60 seconds
- **APK analysis**: 1-5 seconds
- **Anti-cheat scan**: 1-3 seconds

### GPU vs CPU
- GPU: ~3-5x faster on large binaries
- CPU (NumPy): Slower but reliable fallback
- Memory: GPU uses 2-4 GB for large files

---

## ⚠️ Limitations

- **Python 3.10+ required** for type hints
- **Limited YARA support** (use custom signatures)
- **No network access** for cloud features
- **Windows/Linux/Mac** - tested on Windows
- **NVIDIA GPU optional** - falls back to NumPy

---

## 📞 Support

For issues or suggestions:
1. Check comprehensive_test_suite.py for examples
2. Review gui_app.py documentation
3. Check module docstrings
4. Verify all dependencies installed

---

## 📜 Version

**E-BOX 512 RE Tool v3.2**
- GPU acceleration
- APK analysis
- Anti-cheat detection
- Enhanced GUI with copy functionality
- Comprehensive test suite

**Status**: Production Ready ✅

---

## 📄 License

Internal tool for reverse engineering and security research.

---

**Last Updated**: April 2026
**Author**: Omsin
**GPU Support**: GTX 850M (and compatible)
