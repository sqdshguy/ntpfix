#Requires -RunAsAdministrator
# Uninstall NtpFix and re-enable built-in NTP client

$ErrorActionPreference = "Stop"
$providerKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"

Write-Host "Stopping w32time..." -ForegroundColor Cyan
net stop w32time 2>$null

Write-Host "Removing NtpFix provider..." -ForegroundColor Cyan
Remove-Item -Path "$providerKey\NtpFix" -Recurse -ErrorAction SilentlyContinue

Write-Host "Re-enabling built-in NTP client..." -ForegroundColor Cyan
Set-ItemProperty -Path "$providerKey\NtpClient" -Name "Enabled" -Value 1 -Type DWord

Write-Host "Restarting w32time..." -ForegroundColor Cyan
net start w32time

Write-Host "Cleaning up DLL..." -ForegroundColor Cyan
Remove-Item "C:\Windows\System32\ntpfix.dll" -ErrorAction SilentlyContinue

Write-Host "Done. Built-in NTP client restored." -ForegroundColor Green
