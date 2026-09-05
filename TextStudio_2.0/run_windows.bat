@echo off
setlocal
set HERE=%~dp0
if exist "%HERE%.venv\Scripts\pythonw.exe" (
  "%HERE%.venv\Scripts\pythonw.exe" "%HERE%TextStudio.pyw" %*
) else (
  py -3 "%HERE%TextStudio.pyw" %*
)
endlocal
