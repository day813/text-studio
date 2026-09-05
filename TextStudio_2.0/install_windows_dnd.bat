@echo off
setlocal
set HERE=%~dp0
py -3 -m venv "%HERE%.venv"
"%HERE%.venv\Scripts\python.exe" -m pip install --upgrade pip
"%HERE%.venv\Scripts\python.exe" -m pip install -r "%HERE%requirements.txt" -r "%HERE%requirements-dnd.txt"
echo.
echo Done. Run run_windows.bat
pause
endlocal
