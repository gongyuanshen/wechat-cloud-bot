@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo CLOUD SERVER ONLY: host binding is loaded from cloud-deployment.private.json
echo Cloud bot build: 2026-11-01.bot7
if not exist "cloud-deployment.private.json" (
  echo Missing cloud-deployment.private.json. Copy and fill cloud-deployment.example.json first.
  set "bot_result=1"
  goto finished
)
python -X utf8 -c "from cloud_bot import check_environment; check_environment()"
if errorlevel 1 goto failed
if not exist "cloud-bot.private.json" (
  echo Missing cloud-bot.private.json. Put the separate private config beside this launcher.
  set "bot_result=1"
  goto finished
)
if not exist "bot-settings.json" (
  echo Missing bot-settings.json. Copy and fill bot-settings.example.json first.
  set "bot_result=1"
  goto finished
)
if exist ".bot-venv\Scripts\python.exe" goto install
echo Creating the isolated bot environment...
python -m venv ".bot-venv"
if errorlevel 1 goto failed
:install
echo Installing hash-pinned dependencies from official PyPI. Internet access is required.
set "PIP_CONFIG_FILE=nul"
".bot-venv\Scripts\python.exe" -m pip --isolated install --disable-pip-version-check --index-url https://pypi.org/simple --only-binary=:all: --require-hashes -r requirements-cloud-runtime.txt
if errorlevel 1 goto failed
".bot-venv\Scripts\python.exe" -m pip --isolated check
if errorlevel 1 goto failed
".bot-venv\Scripts\python.exe" -X utf8 cloud_bot.py
set "bot_result=%errorlevel%"
goto finished
:failed
set "bot_result=%errorlevel%"
echo Setup failed. Keep the final error text; do not rerun repeatedly.
:finished
echo.
echo Exit code: %bot_result%
echo Share runtime\bot-status.json and the final error only. Never share the private config or runtime\ai.
pause
exit /b %bot_result%
