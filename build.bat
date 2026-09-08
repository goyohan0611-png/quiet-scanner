@echo off
rem Wrapper so the window never vanishes without a message.
cd /d "%~dp0"
cmd /k "scripts\build_electron.bat"
