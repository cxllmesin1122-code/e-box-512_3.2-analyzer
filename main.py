"""
E-BOX 512 RE Tool  v3.2 — Entry Point
Run: python main.py
"""

import sys
import os

# ── Minimum Python check ────────────────────────────────────────────────────
if sys.version_info < (3, 10):
    print(f"[ERROR] Python 3.10+ required (got {sys.version})")
    sys.exit(1)

# ── Add project dir to path ─────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── Startup banner ───────────────────────────────────────────────────────────
BANNER = r"""
  ███████╗      ██████╗  ██████╗ ██╗  ██╗    ███████╗ ██╗██████╗
  ██╔════╝      ██╔══██╗██╔═══██╗╚██╗██╔╝    ██╔════╝███║╚════██╗
  █████╗  █████╗██████╔╝██║   ██║ ╚███╔╝     ███████╗╚██║ █████╔╝
  ██╔══╝  ╚════╝██╔══██╗██║   ██║ ██╔██╗     ╚════██║ ██║██╔═══╝
  ███████╗      ██████╔╝╚██████╔╝██╔╝ ██╗    ███████║ ██║███████╗
  ╚══════╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝    ╚══════╝ ╚═╝╚══════╝
  V3.2  Deterministic Binary Analysis System  — by Omsin
"""

def _check_imports() -> list:
    """Return list of missing critical packages."""
    missing = []
    checks = [
        ('numpy',    'NumPy',      True),
        ('scipy',    'SciPy',      False),
        ('capstone', 'Capstone',   True),
        ('elftools', 'pyelftools', False),
        ('tkinter',  'Tkinter',    True),
    ]
    for mod, name, critical in checks:
        try:
            __import__(mod)
        except ImportError:
            if critical:
                missing.append(name)
            else:
                print(f"  [WARN] Optional package missing: {name} "
                      f"(some features limited)")
    return missing


def main():
    print(BANNER)
    print(f"  Python {sys.version.split()[0]}")

    # GPU probe
    try:
        import cupy as cp
        cp.array([1])
        print("  GPU: CuPy active ✓  (GTX 850M)")
    except ImportError:
        print("  GPU: CuPy not available — NumPy CPU fallback")
    except Exception as e:
        print(f"  GPU: CuPy installed but error: {e} — NumPy fallback")

    print()

    # Dependency check
    missing = _check_imports()
    if missing:
        print(f"  [CRITICAL] Missing required packages: {', '.join(missing)}")
        print("  Run setup.bat to install all dependencies.")
        input("  Press Enter to exit…")
        sys.exit(1)

    print("  All critical dependencies OK — launching GUI…\n")

    # Launch
    try:
        from gui_app import main as gui_main
        gui_main()
    except Exception as ex:
        import traceback
        print(f"\n[FATAL] GUI crashed: {ex}")
        traceback.print_exc()
        input("Press Enter to exit…")
        sys.exit(1)


if __name__ == '__main__':
    main()
