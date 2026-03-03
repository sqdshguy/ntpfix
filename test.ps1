<#
.SYNOPSIS
    Test NtpFix before installing. Verifies NTP works from ephemeral ports
    and that the DLL loads correctly as a time provider.
#>

$ErrorActionPreference = "Continue"
$pass = 0
$fail = 0

function Test($name, $result, $detail) {
    if ($result) {
        Write-Host "  PASS  " -ForegroundColor Green -NoNewline
        Write-Host "$name"
        $script:pass++
    } else {
        Write-Host "  FAIL  " -ForegroundColor Red -NoNewline
        Write-Host "$name"
        if ($detail) { Write-Host "        $detail" -ForegroundColor DarkGray }
        $script:fail++
    }
}

Write-Host ""
Write-Host "=== NtpFix Test Suite ===" -ForegroundColor Cyan
Write-Host ""

# -------------------------------------------------------
Write-Host "[1/6] Network: NTP from ephemeral port" -ForegroundColor Yellow
# -------------------------------------------------------
$ntpOk = $false
$offset = $null
try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = 5000
    $packet = [byte[]]::new(48)
    $packet[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
    $udp.Send($packet, 48, "216.239.35.8", 123) | Out-Null
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $resp = $udp.Receive([ref]$ep)
    $srcPort = $udp.Client.LocalEndPoint.Port
    $udp.Close()
    $ntpOk = ($resp.Length -eq 48)
    # Check response mode = 4 (server)
    $mode = $resp[0] -band 0x07
    $stratum = $resp[1]
} catch {
    $udp.Close() 2>$null
}

Test "NTP response received (48 bytes)" $ntpOk
Test "Response is server mode (mode=4)" ($mode -eq 4)
Test "Valid stratum ($stratum)" ($stratum -ge 1 -and $stratum -le 15)
Test "Used ephemeral source port ($srcPort)" ($srcPort -gt 1024)

# -------------------------------------------------------
Write-Host ""
Write-Host "[2/6] Network: Port 123 is blocked (confirming the ISP bug)" -ForegroundColor Yellow
# -------------------------------------------------------
$port123Blocked = $false
try {
    # Stop w32time so we can bind to 123
    $w32Running = (Get-Service w32time -ErrorAction SilentlyContinue).Status -eq "Running"
    if ($w32Running) { net stop w32time 2>$null | Out-Null }

    $udp2 = New-Object System.Net.Sockets.UdpClient(123)
    $udp2.Client.ReceiveTimeout = 3000
    $udp2.Send($packet, 48, "216.239.35.8", 123) | Out-Null
    $ep2 = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    try {
        $resp2 = $udp2.Receive([ref]$ep2)
        $port123Blocked = $false
    } catch {
        $port123Blocked = $true
    }
    $udp2.Close()

    if ($w32Running) { net start w32time 2>$null | Out-Null }
} catch {
    # Can't bind to 123 (w32time might still hold it) - skip
    $port123Blocked = $null
    $udp2.Close() 2>$null
    if ($w32Running) { net start w32time 2>$null | Out-Null }
}

if ($port123Blocked -eq $null) {
    Write-Host "  SKIP  " -ForegroundColor DarkGray -NoNewline
    Write-Host "Port 123 test (couldn't bind, w32time may hold it)"
} else {
    Test "Port 123 is blocked by ISP (confirming the bug)" $port123Blocked
}

# -------------------------------------------------------
Write-Host ""
Write-Host "[3/6] NTP offset calculation" -ForegroundColor Yellow
# -------------------------------------------------------
$stripOutput = w32tm /stripchart /computer:time.google.com /dataonly /samples:1 2>&1
$stripLine = ($stripOutput | Select-Object -Last 1) -as [string]
$offsetMatch = [regex]::Match($stripLine, '([+-]?\d+\.\d+)s')
if ($offsetMatch.Success) {
    $offsetSec = [double]$offsetMatch.Groups[1].Value
    $offsetMs = [math]::Abs($offsetSec * 1000)
    Test "Stripchart offset: ${offsetSec}s (${offsetMs}ms)" $true
    Test "Clock drift < 5 seconds" ($offsetMs -lt 5000) "Offset: ${offsetSec}s"
} else {
    Test "Stripchart returned valid offset" $false "$stripLine"
}

# -------------------------------------------------------
Write-Host ""
Write-Host "[4/6] DLL build check" -ForegroundColor Yellow
# -------------------------------------------------------
$dllExists = Test-Path "ntpfix.dll"
Test "ntpfix.dll exists" $dllExists "Run build.bat first"

if ($dllExists) {
    $dllInfo = Get-Item "ntpfix.dll"
    Test "DLL size > 0 bytes ($($dllInfo.Length) bytes)" ($dllInfo.Length -gt 0)

    # Verify exports
    try {
        $exports = & dumpbin /exports ntpfix.dll 2>$null
        if ($exports) {
            $hasOpen    = $exports | Select-String "TimeProvOpen"
            $hasCommand = $exports | Select-String "TimeProvCommand"
            $hasClose   = $exports | Select-String "TimeProvClose"
            $hasReg     = $exports | Select-String "Register"
            Test "Export: TimeProvOpen" ($hasOpen -ne $null)
            Test "Export: TimeProvCommand" ($hasCommand -ne $null)
            Test "Export: TimeProvClose" ($hasClose -ne $null)
            Test "Export: Register" ($hasReg -ne $null)
        } else {
            # Try with objdump (MinGW)
            $exports = & objdump -p ntpfix.dll 2>$null | Select-String "TimeProvOpen|TimeProvCommand|TimeProvClose|Register"
            if ($exports) {
                Test "DLL exports found (objdump)" ($exports.Count -ge 4)
            } else {
                Write-Host "  SKIP  " -ForegroundColor DarkGray -NoNewline
                Write-Host "Export check (no dumpbin/objdump available)"
            }
        }
    } catch {
        Write-Host "  SKIP  " -ForegroundColor DarkGray -NoNewline
        Write-Host "Export check (tool not available)"
    }
}

# -------------------------------------------------------
Write-Host ""
Write-Host "[5/6] Registration check" -ForegroundColor Yellow
# -------------------------------------------------------
$regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpFix"
$isRegistered = Test-Path $regKey
if ($isRegistered) {
    $regEnabled = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).Enabled
    $regInput   = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).InputProvider
    $regDll     = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).DllName
    Test "NtpFix registered in w32time" $true
    Test "Enabled = 1" ($regEnabled -eq 1)
    Test "InputProvider = 1" ($regInput -eq 1)
    Test "DllName points to file" (Test-Path $regDll -ErrorAction SilentlyContinue) "$regDll"

    # Check if built-in NTP client is disabled
    $ntpClientKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient"
    $ntpClientEnabled = (Get-ItemProperty $ntpClientKey -ErrorAction SilentlyContinue).Enabled
    Test "Built-in NtpClient disabled" ($ntpClientEnabled -eq 0) "Enabled=$ntpClientEnabled"

    # Check w32time status
    Write-Host ""
    Write-Host "  Current w32time status:" -ForegroundColor DarkGray
    $status = w32tm /query /status 2>&1
    $source = ($status | Select-String "Source:").ToString().Trim()
    Write-Host "  $source" -ForegroundColor DarkGray
    $isNtpFix = $source -match "NtpFix"
    Test "w32time source is NtpFix" $isNtpFix "May need ~60s after install. $source"
} else {
    Write-Host "  SKIP  " -ForegroundColor DarkGray -NoNewline
    Write-Host "NtpFix not installed yet (run install.ps1)"
}

# -------------------------------------------------------
Write-Host ""
Write-Host "[6/6] Service startup check" -ForegroundColor Yellow
# -------------------------------------------------------
$svc = Get-Service w32time -ErrorAction SilentlyContinue
if ($svc) {
    Test "w32time is running" ($svc.Status -eq "Running") "Status: $($svc.Status)"
    $isAuto = $svc.StartType -eq "Automatic"
    Test "w32time starts automatically on boot" $isAuto "StartType: $($svc.StartType). Fix: Set-Service w32time -StartupType Automatic"
} else {
    Test "w32time service exists" $false "Service not found"
}

# -------------------------------------------------------
Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "  Results: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

if ($fail -eq 0 -and -not $isRegistered) {
    Write-Host "All pre-install checks passed. Ready to install:" -ForegroundColor Green
    Write-Host "  .\install.ps1" -ForegroundColor White
} elseif ($fail -eq 0) {
    Write-Host "Everything looks good!" -ForegroundColor Green
} else {
    Write-Host "Some checks failed. Review the output above." -ForegroundColor Yellow
}
