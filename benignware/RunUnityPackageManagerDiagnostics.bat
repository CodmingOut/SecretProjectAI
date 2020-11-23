@echo off

"%~dp0\bin\UnityPackageManagerDiagnostics.exe" "-o" "%UPM_DIAG_REPORT_PATH%" "-p" "%UPM_DIAG_UPM_PATH%"

set exit_code=%ERRORLEVEL%

echo.
pause

exit /b %exit_code%