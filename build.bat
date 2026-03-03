@echo off
REM Build NtpFix - Custom Windows Time Provider
REM
REM Option 1: MSVC (Visual Studio Developer Command Prompt)
REM Option 2: MinGW (gcc)
REM Option 3: TinyCC (tcc)

where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo Building with MSVC...
    cl /LD /O2 /W4 ntpfix.c ws2_32.lib advapi32.lib user32.lib /Fe:ntpfix.dll
    goto done
)

where gcc >nul 2>nul
if %errorlevel% equ 0 (
    echo Building with MinGW...
    gcc -shared -O2 -Wall -o ntpfix.dll ntpfix.c -lws2_32 -ladvapi32 -luser32
    goto done
)

where tcc >nul 2>nul
if %errorlevel% equ 0 (
    echo Building with TCC...
    tcc -shared -o ntpfix.dll ntpfix.c -lws2_32 -ladvapi32 -luser32
    goto done
)

echo ERROR: No C compiler found.
echo Install one of: Visual Studio, MinGW, or TinyCC
exit /b 1

:done
if exist ntpfix.dll (
    echo.
    echo Build successful: ntpfix.dll
    echo.
    echo To install (run as Administrator):
    echo   copy ntpfix.dll C:\Windows\System32\ntpfix.dll
    echo   rundll32 C:\Windows\System32\ntpfix.dll,Register
    echo   reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" /v Enabled /t REG_DWORD /d 0 /f
    echo   net stop w32time ^&^& net start w32time
) else (
    echo Build failed.
)
