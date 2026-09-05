@echo off
setlocal
set HERE=%~dp0
if not exist "%HERE%.venv\Scripts\python.exe" (
  py -3 -m venv "%HERE%.venv"
)
"%HERE%.venv\Scripts\python.exe" -m pip install pyinstaller paramiko tkinterdnd2
"%HERE%.venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --windowed --name TextStudio --collect-all tkinterdnd2 --collect-all paramiko "%HERE%TextStudio.py"
echo.
echo Built: dist\TextStudio.exe
pause
endlocal
