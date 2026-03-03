# NtpFix

Windows Time Provider DLL that does NTP from ephemeral source ports instead of port 123.

Fixes time sync on networks where the ISP blocks UDP source port 123 as NTP reflection DDoS protection. This breaks Windows' built-in NTP client (`w32time`), which hardcodes source port 123 for all NTP traffic. Every other OS uses a random high port. Windows doesn't.

## The problem

Some ISPs (confirmed on Vinteleport/AS24945 in Ukraine, likely others) drop inbound UDP packets where the source port is 123. This is a blanket anti-DDoS measure that kills `w32time`'s ability to sync:

- `w32time` sends NTP requests from source port 123 to destination port 123
- ISP drops the response because src_port=123
- Service logs "no time data was available," falls back to Local CMOS Clock
- `w32tm /stripchart` still works because it uses an ephemeral port
- Every other NTP client (Linux, macOS, NetTime, chrony) works fine

`w32time` has used source port 123 since Windows 2000. Microsoft's [W32Time repo] has 21 open issues and zero responses.

## Install

Download `ntpfix.zip` from [Releases] and extract. Run PowerShell as Administrator:

```powershell
.\install.ps1
```

This copies the DLL to System32, registers it as a time provider, disables the built-in NTP client, sets `w32time` to start automatically, and restarts the service.

Wait about 30 seconds, then verify:

```powershell
w32tm /query /status
```

Source should show `NtpFix:time.google.com` with Stratum 2.

## Uninstall

```powershell
.\uninstall.ps1
```

Re-enables the built-in NTP client and removes NtpFix.

## How it works

NtpFix is a Windows Time Provider DLL. The `w32time` service loads it, and it provides time samples just like the built-in `NtpClient` provider, except it sends NTP queries from whatever port the OS assigns (ephemeral, typically 49152-65535) instead of binding to port 123.

Polls [time.google.com] (216.239.35.0/4/8/12) every 64 seconds, round-robin. Computes offset using the standard NTP formula: `offset = ((T2-T1) + (T3-T4)) / 2`.

Exports the three required Time Provider functions (`TimeProvOpen`, `TimeProvCommand`, `TimeProvClose`) plus `Register`/`Deregister` helpers callable via `rundll32`.

## Testing

`test.ps1` runs pre- and post-install checks:

1. NTP works from an ephemeral port
2. NTP from port 123 is blocked (confirms the ISP bug)
3. Clock offset via `w32tm /stripchart`
4. DLL exists and has correct exports
5. Provider registration and NtpClient disabled
6. `w32time` is running and set to auto-start

`diag.ps1` dumps service status, provider config, and event logs for troubleshooting.

## Building from source

MSVC (Visual Studio Developer Command Prompt):
```
cl /LD /O2 /W4 ntpfix.c ws2_32.lib advapi32.lib user32.lib /Fe:ntpfix.dll
```

MinGW (including cross-compile from macOS/Linux):
```
x86_64-w64-mingw32-gcc -shared -O2 -Wall -o ntpfix.dll ntpfix.c -lws2_32 -ladvapi32 -luser32
```

CI builds with MSVC on `windows-latest` and runs an integration test that simulates the ISP port block with a Windows Firewall rule, then verifies NtpFix syncs through it.

## Files

| File | What |
|------|------|
| `ntpfix.c` | The DLL. Single file, no dependencies beyond Win32. |
| `install.ps1` | Install and register. Requires admin. |
| `uninstall.ps1` | Remove and re-enable built-in NTP. |
| `test.ps1` | Test suite (pre/post install). |
| `diag.ps1` | Diagnostic dump for troubleshooting. |
| `test_ntp.c` | NTP logic tests (macOS/Linux). |

[W32Time repo]: https://github.com/microsoft/W32Time
[Releases]: https://github.com/sqdshguy/ntpfix/releases
[time.google.com]: https://developers.google.com/time
