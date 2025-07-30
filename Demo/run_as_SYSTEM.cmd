:: File: Demo/run_as_SYSTEM.cmd
:: Project: KernelMode

@echo off
echo [+] Attempting to launch SYSTEM shell...
whoami
echo.

echo [+] Running cmd.exe with elevated privileges (if token was stolen)...
cmd.exe

exit /b
