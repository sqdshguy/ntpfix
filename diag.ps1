<#
.SYNOPSIS
    NtpFix diagnostic script. Run as Administrator after install.
#>

Write-Host ""
Write-Host "=== NtpFix Diagnostics ===" -ForegroundColor Cyan
Write-Host ""

# 1. w32time service status
Write-Host "[1/6] w32time service" -ForegroundColor Yellow
$svc = Get-Service w32time -ErrorAction SilentlyContinue
Write-Host "  Status: $($svc.Status)"
Write-Host "  StartType: $($svc.StartType)"

# 2. w32time source and stratum
Write-Host ""
Write-Host "[2/6] w32time sync status" -ForegroundColor Yellow
$status = w32tm /query /status 2>&1
$status | ForEach-Object { Write-Host "  $_" }

# 3. Provider registration
Write-Host ""
Write-Host "[3/6] Time providers" -ForegroundColor Yellow
$providers = @("NtpFix", "NtpClient", "VMICTimeProvider")
foreach ($p in $providers) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\$p"
    if (Test-Path $key) {
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $en = if ($props.Enabled -eq 1) { "ENABLED" } else { "disabled" }
        $color = if ($props.Enabled -eq 1) { "Green" } else { "DarkGray" }
        Write-Host "  $p" -ForegroundColor $color -NoNewline
        Write-Host " = $en" -ForegroundColor $color -NoNewline
        if ($props.DllName) { Write-Host "  ($($props.DllName))" -ForegroundColor DarkGray } else { Write-Host "" }
    } else {
        Write-Host "  $p = not registered" -ForegroundColor DarkGray
    }
}

# 4. DLL file check
Write-Host ""
Write-Host "[4/6] DLL file" -ForegroundColor Yellow
$dllPath = "C:\Windows\System32\ntpfix.dll"
if (Test-Path $dllPath) {
    $info = Get-Item $dllPath
    Write-Host "  $dllPath exists ($($info.Length) bytes, $($info.LastWriteTime))"
} else {
    Write-Host "  $dllPath NOT FOUND" -ForegroundColor Red
}

# 5. NtpFix event log
Write-Host ""
Write-Host "[5/6] NtpFix event log (last 20)" -ForegroundColor Yellow
$events = Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='NtpFix']]]" -MaxEvents 20 -ErrorAction SilentlyContinue
if ($events) {
    $events | ForEach-Object {
        Write-Host "  $($_.TimeCreated): $($_.Message)"
    }
} else {
    Write-Host "  No NtpFix events found" -ForegroundColor Red
    Write-Host "  (DLL may not be loading - check w32time service)" -ForegroundColor DarkGray
}

# 6. Time Service events
Write-Host ""
Write-Host "[6/6] Windows Time Service events (last 10)" -ForegroundColor Yellow
$tsEvents = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Time-Service']]]" -MaxEvents 10 -ErrorAction SilentlyContinue
if ($tsEvents) {
    $tsEvents | ForEach-Object {
        $msg = ($_.Message -split "`n")[0].Trim()
        Write-Host "  $($_.TimeCreated): $msg"
    }
} else {
    Write-Host "  No Time Service events found" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
