@echo off
rem ============================================================
rem  Quiet Scanner build
rem
rem  NOTE: keep this file ASCII-only.
rem  cmd.exe reads .bat in the system OEM codepage (949 on Korean
rem  Windows). Korean text saved as UTF-8 breaks parsing and the
rem  window closes instantly with no message.
rem ============================================================
setlocal
rem  This script now lives in scripts\ - step up so every path below
rem  is relative to the project root, the way it was before the move.
cd /d "%~dp0.."

set "LOG=%CD%\build.log"
echo Quiet Scanner build log > "%LOG%"
echo. >> "%LOG%"

echo.
echo ============================================
echo   Quiet Scanner build
echo ============================================
echo   log: build.log
echo.

rem ---- 0. close anything holding the files ----------------------
echo [0/4] closing running app...
taskkill /f /im "Quiet Scanner.exe"    >nul 2>&1
taskkill /f /im "IPFix Studio.exe"  >nul 2>&1
taskkill /f /im "IPFixBackend.exe"  >nul 2>&1
rem  Clear BOTH output folders, not just dist.
rem
rem  electron-builder deletes the old win-unpacked itself before writing a new
rem  one. Inside a OneDrive folder that rmdir hits EBUSY: OneDrive (or Defender)
rem  still holds a handle on the 112 MB files from the previous run. The build
rem  then dies at step 4 with "resource busy or locked".
rem
rem  So we clear them here, and we retry - those locks are usually released a
rem  second or two later.
call :nuke "electron\dist\win-unpacked.tmp"
call :nuke "electron\dist\win-unpacked"
call :nuke "electron\installer\win-unpacked.tmp"
call :nuke "electron\installer\win-unpacked"

rem ---- check tools ---------------------------------------------
where python >nul 2>&1
if errorlevel 1 (
  echo    ERROR: python not found in PATH.
  echo    Install Python 3.12 and tick "Add python.exe to PATH".
  goto :fail
)
where npm >nul 2>&1
if errorlevel 1 (
  echo    ERROR: npm not found in PATH.
  echo    Install Node.js LTS from https://nodejs.org
  goto :fail
)

rem ---- check data files ----------------------------------------
if not exist "src\oui.dat.gz" (
  echo    ERROR: src\oui.dat.gz missing.
  goto :fail
)
if not exist "scripts\IPFixBackend.spec" (
  echo    ERROR: scripts\IPFixBackend.spec missing.
  goto :fail
)

rem ---- 1. python engine ----------------------------------------
rem  Must build through the .spec file.
rem  Passing electron-backend.py directly makes PyInstaller
rem  overwrite the .spec and drop the vendor database.
echo [1/4] building python engine...
rem  Pin the output folders. Without them PyInstaller writes dist\ next to
rem  the .spec (scripts\dist), and the check below - which looks in the root
rem  dist\ - fails with "vendor database was not bundled".
python -m PyInstaller --noconfirm --clean --distpath dist --workpath build scripts\IPFixBackend.spec >> "%LOG%" 2>&1
if errorlevel 1 (
  echo    ERROR: PyInstaller failed. See build.log
  goto :fail
)

if not exist "dist\IPFixBackend\_internal\oui.dat.gz" (
  echo    ERROR: vendor database was not bundled.
  echo    Check the datas list in scripts\IPFixBackend.spec
  goto :fail
)
echo        vendor database + device book bundled OK

if exist "IPFixBackend" rmdir /s /q "IPFixBackend"
xcopy /e /i /y "dist\IPFixBackend" "IPFixBackend" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo    ERROR: could not copy backend folder.
  goto :fail
)

rem ---- 2. electron deps ----------------------------------------
echo [2/4] checking electron dependencies...
cd electron
if not exist "node_modules" (
  call npm install >> "%LOG%" 2>&1
  if errorlevel 1 (
    echo    ERROR: npm install failed. See build.log
    cd ..
    goto :fail
  )
)

rem ---- 3. package ----------------------------------------------
echo [3/4] packaging app...
call npm run build >> "%LOG%" 2>&1
if errorlevel 1 (
  echo    ERROR: packaging failed. See build.log
  cd ..
  goto :fail
)

rem ---- 4. installer --------------------------------------------
echo [4/4] building installer...
call npm run build:installer >> "%LOG%" 2>&1
if errorlevel 1 (
  echo    ERROR: installer build failed. See build.log
  cd ..
  goto :fail
)
cd ..

echo.
echo ============================================
echo   DONE
echo ============================================
echo   run       : electron\dist\win-unpacked\Quiet Scanner.exe
echo   installer : electron\installer\
echo.
pause
exit /b 0

:nuke
rem  %~1 = folder to remove. Tries 5 times, 3 seconds apart.
if not exist %1 goto :eof
set "_try=0"
:nuke_again
rmdir /s /q %1 >nul 2>&1
if not exist %1 goto :eof
set /a _try+=1
if %_try% geq 5 (
  echo    WARNING: could not delete %1
  echo    Pause OneDrive ^(tray icon - Pause syncing^) and run this again.
  goto :eof
)
echo        waiting for %1 to unlock... ^(%_try%/5^)
timeout /t 3 /nobreak >nul
goto :nuke_again

:fail
echo.
echo ============================================
echo   BUILD FAILED
echo ============================================
echo.
echo   Common causes:
echo     - OneDrive sync lock     : pause OneDrive, then retry   ^<-- most common
echo     - app still running      : close all Quiet Scanner windows
echo     - stale build folder     : delete electron\dist and electron\installer
echo     - antivirus locking exe  : exclude this folder
echo     - Node.js not installed  : https://nodejs.org  (LTS)
echo.
echo   Full details are in:  build.log
echo.
pause
exit /b 1
