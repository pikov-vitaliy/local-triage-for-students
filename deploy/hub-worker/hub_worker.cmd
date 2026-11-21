@echo off
rem Hub worker for Local triage: runs hub_worker.py next to this file. ASCII only on purpose.
chcp 65001 >nul
cd /d "%~dp0"
python hub_worker.py %*
set RC=%ERRORLEVEL%
echo.
echo Exit code: %RC%  (0 = stopped normally, 2 = settings or sign-in problem)
pause
exit /b %RC%
