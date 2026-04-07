@echo off
REM E-BOX 512 RE Tool v3.2 — Setup Script for Windows

echo.
echo  ███████╗      ██████╗  ██████╗ ██╗  ██╗    ███████╗ ██╗██████╗
echo  ██╔════╝      ██╔══██╗██╔═══██╗╚██╗██╔╝    ██╔════╝███║╚════██╗
echo  █████╗  █████╗██████╔╝██║   ██║ ╚███╔╝     ███████╗╚██║ █████╔╝
echo  ██╔══╝  ╚════╝██╔══██╗██║   ██║ ██╔██╗     ╚════██║ ██║██╔═══╝
echo  ███████╗      ██████╔╝╚██████╔╝██╔╝ ██╗    ███████║ ██║███████╗
echo  ╚══════╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝    ╚══════╝ ╚═╝╚══════╝
echo.
echo  E-BOX 512 RE Tool v3.2 — Deterministic Binary Analysis
echo  Setup & Dependency Installation Script
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.10+ first.
    echo  https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo  [OK] Python %PYTHON_VERSION% detected

REM Create virtual environment
echo.
echo  Creating virtual environment...
python -m venv .venv
call .venv\Scripts\activate.bat

REM Upgrade pip
echo.
echo  Upgrading pip, setuptools, wheel...
python -m pip install --upgrade pip setuptools wheel

REM Install core dependencies
echo.
echo  Installing core dependencies...
pip install numpy>=1.21.0 scipy>=1.7.0 capstone>=4.0.0 pyelftools>=0.27 zstandard>=0.15.0 lz4>=3.1.0

REM Check for GPU support (CuPy)
echo.
echo  Checking for NVIDIA GPU (CuPy support)...
nvidia-smi >nul 2>&1
if errorlevel 1 (
    echo  [INFO] No NVIDIA GPU detected. Using NumPy CPU fallback.
    echo.
    echo  To enable GPU support later:
    echo.    pip install cupy-cuda11x
    echo.
    echo  (Replace 11x with your CUDA version: e.g., cupy-cuda117)
) else (
    echo  [OK] NVIDIA GPU detected!
    echo  Installing CuPy for GPU acceleration...
    pip install cupy
)

REM Verify installation
echo.
echo  Verifying installation...
python -c "import numpy, scipy, capstone, elftools, zstandard, lz4; print('[OK] All core deps installed')" 2>nul
if errorlevel 1 (
    echo  [WARN] Some packages may have failed to install. Trying pip install --retries 5
    pip install --retries 5 -q -r requirements.txt
)

REM Deactivate venv temporarily to show completion message
REM

echo.
echo  [SUCCESS] Setup complete!
echo.
echo  To activate the environment:
echo.    .venv\Scripts\activate.bat
echo.
echo  Then run:
echo.    python main.py
echo.
echo.press any key to continue...
pause

REM Activate venv for the user
call .venv\Scripts\activate.bat
cls
python main.py
