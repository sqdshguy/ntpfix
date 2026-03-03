#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install NtpFix - Custom Windows Time Provider that uses ephemeral source ports.

.DESCRIPTION
    Builds (if needed), installs, and registers the NtpFix time provider,
    then disables the built-in NTP client which hardcodes source port 123.
#>

$ErrorActionPreference = "Stop"

$dllName = "ntpfix.dll"
$dllDest = "C:\Windows\System32\$dllName"
$providerKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"

# Build if DLL doesn't exist
if (-not (Test-Path $dllName)) {
    Write-Host "Building ntpfix.dll..." -ForegroundColor Cyan

    # Try MSVC first
    $cl = Get-Command cl -ErrorAction SilentlyContinue
    if ($cl) {
        & cl /LD /O2 /W4 ntpfix.c ws2_32.lib advapi32.lib user32.lib /Fe:ntpfix.dll
    } else {
        $gcc = Get-Command gcc -ErrorAction SilentlyContinue
        if ($gcc) {
            & gcc -shared -O2 -Wall -o ntpfix.dll ntpfix.c -lws2_32 -ladvapi32 -luser32
        } else {
            Write-Error "No C compiler found. Install Visual Studio or MinGW, or build ntpfix.dll manually."
            exit 1
        }
    }

    if (-not (Test-Path $dllName)) {
        Write-Error "Build failed."
        exit 1
    }
    Write-Host "Build successful." -ForegroundColor Green
}

# Copy DLL to System32
Write-Host "Copying $dllName to System32..." -ForegroundColor Cyan
Copy-Item $dllName $dllDest -Force

# Register the time provider
Write-Host "Registering NtpFix time provider..." -ForegroundColor Cyan
$ntpFixKey = "$providerKey\NtpFix"
if (-not (Test-Path $ntpFixKey)) {
    New-Item -Path $ntpFixKey -Force | Out-Null
}
Set-ItemProperty -Path $ntpFixKey -Name "DllName"       -Value $dllDest -Type String
Set-ItemProperty -Path $ntpFixKey -Name "Enabled"       -Value 1        -Type DWord
Set-ItemProperty -Path $ntpFixKey -Name "InputProvider"  -Value 1        -Type DWord

# Disable built-in NTP client (it uses port 123 which is blocked)
Write-Host "Disabling built-in NTP client (port 123 is blocked by ISP)..." -ForegroundColor Yellow
Set-ItemProperty -Path "$providerKey\NtpClient" -Name "Enabled" -Value 0 -Type DWord

# Restart w32time
Write-Host "Restarting Windows Time service..." -ForegroundColor Cyan
net stop w32time 2>$null
net start w32time

Start-Sleep -Seconds 5

# Check status
Write-Host ""
Write-Host "=== Status ===" -ForegroundColor Green
& w32tm /query /status
Write-Host ""
Write-Host "=== Providers ===" -ForegroundColor Green
& w32tm /query /configuration | Select-String -Pattern "NtpFix|NtpClient|Enabled|DllName" -Context 0,0

Write-Host ""
Write-Host "Done! NtpFix is now providing time samples from ephemeral ports." -ForegroundColor Green
Write-Host "Check back in ~60 seconds: w32tm /query /status" -ForegroundColor Cyan
