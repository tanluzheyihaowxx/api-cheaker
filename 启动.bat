@echo off
setlocal
cd /d "%~dp0"
set "NODE_EXE=node.exe"
where node.exe >nul 2>nul
if errorlevel 1 (
  if exist "D:\AI\node\node.exe" (
    set "NODE_EXE=D:\AI\node\node.exe"
  ) else (
    echo Node.js 22 or newer is required. Install Node.js and try again.
    pause
    exit /b 1
  )
)
"%NODE_EXE%" -e "if(Number(process.versions.node.split('.')[0])<22)process.exit(1)"
if errorlevel 1 (
  echo Please upgrade Node.js to version 22 or newer.
  pause
  exit /b 1
)
"%NODE_EXE%" server.mjs
pause
