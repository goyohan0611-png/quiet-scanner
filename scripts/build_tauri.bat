@echo off
setlocal
cd /d "%~dp0.."
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js LTS, then try again.
  exit /b 1
)
where cargo >nul 2>nul
if errorlevel 1 (
  echo Rust MSVC is required. Install Rust and Microsoft C++ Build Tools.
  exit /b 1
)
echo [1/2] Preparing the Tauri build tools...
call npm ci
if errorlevel 1 exit /b 1
echo [2/2] Building Quiet Scanner and the Windows installer...
call npm run build -- --bundles nsis
if errorlevel 1 (
  echo Build failed. Check the error above.
  exit /b 1
)
echo.
echo Installer: src-tauri\target\release\bundle\nsis
exit /b 0
