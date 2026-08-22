@echo off
REM ====================================================================
REM NMD Windows Standalone Executable Build Script
REM ====================================================================

echo [*] Starting NMD Windows Desktop App Build Process...

REM 1. Activate virtual environment if present
if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment .venv...
    call .venv\Scripts\activate.bat
)

REM 2. Install / Upgrade build dependencies
echo [*] Installing requirements...
pip install -r requirements.txt

REM 3. Clean previous build artifacts
echo [*] Cleaning previous build folders (dist/, build/)...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"

REM 4. Execute PyInstaller
echo [*] Compiling executable with PyInstaller...
pyinstaller --clean build_windows.spec

REM 5. Verify Build Output
if exist "dist\NMD\NMD-Security-Dashboard.exe" (
    echo ====================================================================
    echo [SUCCESS] NMD Windows Desktop Application successfully built!
    echo [OUTPUT] Executable path: dist\NMD\NMD-Security-Dashboard.exe
    echo ====================================================================
) else (
    echo [ERROR] Build failed. Output executable not found.
    exit /b 1
)
