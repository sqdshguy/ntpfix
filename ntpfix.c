/*
 * NtpFix - Custom Windows Time Provider
 *
 * Fixes w32time's broken NTP client that hardcodes source port 123,
 * which gets blocked by ISPs with NTP reflection DDoS protection.
 *
 * This Time Provider does NTP from ephemeral source ports, like
 * every other sane NTP client on every other OS.
 *
 * Build (MSVC):  cl /LD ntpfix.c ws2_32.lib advapi32.lib /Fe:ntpfix.dll
 * Build (MinGW): gcc -shared -o ntpfix.dll ntpfix.c -lws2_32 -ladvapi32
 *
 * Install:   rundll32 ntpfix.dll,Register
 * Uninstall: rundll32 ntpfix.dll,Deregister
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ================================================================
 * TimeProv.h definitions (inline so no Windows SDK needed)
 * From: Windows SDK 10.0 / TimeProv.h
 * ================================================================ */

typedef void *TimeProvHandle;

typedef enum {
    TPC_TimeJumped          = 0,
    TPC_UpdateConfig        = 1,
    TPC_PollIntervalChanged = 2,
    TPC_GetSamples          = 3,
    TPC_NetTopoChange       = 4,
    TPC_Query               = 5,
    TPC_Shutdown            = 6,
} TimeProvCmd;

typedef enum {
    TSI_LastSyncTime        = 0,
    TSI_ClockTickSize       = 1,
    TSI_ClockPrecision      = 2,
    TSI_CurrentTime         = 3,
    TSI_PhaseOffset         = 4,
    TSI_TickCount           = 5,
    TSI_LeapFlags           = 6,
    TSI_Stratum             = 7,
    TSI_ReferenceIdentifier = 8,
    TSI_PollInterval        = 9,
    TSI_RootDelay           = 10,
    TSI_RootDispersion      = 11,
    TSI_TSFlags             = 12,
} TimeSysInfo;

typedef HRESULT (__stdcall *GetTimeSysInfoFunc)(TimeSysInfo eInfo, void *pvInfo);
typedef HRESULT (__stdcall *LogTimeProvEventFunc)(WORD wType, WCHAR *wszProvName, WCHAR *wszMessage);
typedef HRESULT (__stdcall *AlertSamplesAvailFunc)(void);
typedef HRESULT (__stdcall *SetProviderStatusFunc)(void *pspsi);

typedef struct {
    DWORD dwSize;
    GetTimeSysInfoFunc     pfnGetTimeSysInfo;
    LogTimeProvEventFunc   pfnLogTimeProvEvent;
    AlertSamplesAvailFunc  pfnAlertSamplesAvail;
    SetProviderStatusFunc  pfnSetProviderStatus;
} TimeProvSysCallbacks;

typedef struct {
    DWORD              dwSize;
    DWORD              dwRefid;
    signed __int64     toOffset;
    signed __int64     toDelay;
    unsigned __int64   tpDispersion;
    unsigned __int64   nSysTickCount;
    signed __int64     nSysPhaseOffset;
    BYTE               nLeapFlags;
    BYTE               nStratum;
    DWORD              dwTSFlags;
    WCHAR              wszUniqueName[256];
} TimeSample;

typedef struct {
    BYTE  *pbSampleBuf;
    DWORD  cbSampleBuf;
    DWORD  dwSamplesReturned;
    DWORD  dwSamplesAvailable;
} TpcGetSamplesArgs;

/* ================================================================
 * NTP protocol
 * ================================================================ */

#pragma pack(push, 1)
typedef struct {
    BYTE  li_vn_mode;     /* LI(2) | VN(3) | Mode(3) */
    BYTE  stratum;
    BYTE  poll;
    BYTE  precision;
    DWORD root_delay;     /* NTP short format: 16.16 fixed point */
    DWORD root_dispersion;
    DWORD ref_id;
    DWORD ref_ts_sec;
    DWORD ref_ts_frac;
    DWORD orig_ts_sec;
    DWORD orig_ts_frac;
    DWORD recv_ts_sec;
    DWORD recv_ts_frac;
    DWORD tx_ts_sec;
    DWORD tx_ts_frac;
} NtpPacket;
#pragma pack(pop)

/*
 * Epoch conversion:
 * FILETIME epoch: 1601-01-01 00:00:00 UTC (100ns ticks)
 * NTP epoch:      1900-01-01 00:00:00 UTC (seconds + fraction)
 * Difference:     9435484800 seconds = 94354848000000000 (100ns ticks)
 */
#define NTP_FILETIME_OFFSET 94354848000000000ULL

/* Convert FILETIME to NTP-epoch 100ns ticks */
static __int64 ft_to_ntp100ns(FILETIME ft) {
    ULARGE_INTEGER ul;
    ul.LowPart  = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (__int64)(ul.QuadPart - NTP_FILETIME_OFFSET);
}

/* Convert NTP timestamp (network byte order) to NTP-epoch 100ns ticks */
static __int64 ntp_to_100ns(DWORD sec_net, DWORD frac_net) {
    DWORD sec  = ntohl(sec_net);
    DWORD frac = ntohl(frac_net);
    return (__int64)sec * 10000000LL +
           ((__int64)frac * 10000000LL) / 4294967296LL;
}

/* Convert NTP short format (16.16 fixed, network order) to 100ns ticks */
static __int64 ntp_short_to_100ns(DWORD val_net) {
    DWORD val = ntohl(val_net);
    DWORD sec  = val >> 16;
    DWORD frac = val & 0xFFFF;
    return (__int64)sec * 10000000LL +
           ((__int64)frac * 10000000LL) / 65536LL;
}

/* ================================================================
 * NTP servers (time.google.com IPs)
 * ================================================================ */

static const char *g_servers[] = {
    "216.239.35.0",
    "216.239.35.4",
    "216.239.35.8",
    "216.239.35.12",
};
#define NUM_SERVERS (sizeof(g_servers) / sizeof(g_servers[0]))

/* ================================================================
 * Provider state
 * ================================================================ */

static TimeProvSysCallbacks g_sc;
static HANDLE               g_hThread    = NULL;
static HANDLE               g_hStopEvent = NULL;
static CRITICAL_SECTION     g_cs;
static BOOL                 g_hasSample  = FALSE;
static TimeSample           g_sample;
static unsigned __int64     g_baseDispersion = 0; /* dispersion at measurement time */
static unsigned __int64     g_sampleTickCount = 0; /* tick count when sample was taken */
static WCHAR                g_wzDllPath[MAX_PATH];
static int                  g_serverIdx  = 0;

/*
 * Per-server KoD state (RFC 5905 Section 7.4).
 * skip_polls: remaining poll cycles to skip this server.
 *   DENY/RSTR: set to KOD_DENY_SKIP (permanent-ish blacklist).
 *   RATE:      doubles each time, capped at KOD_RATE_MAX_SKIP.
 */
static int                  g_serverSkip[4]; /* NUM_SERVERS */
#define KOD_DENY            0x44454E59  /* "DENY" */
#define KOD_RSTR            0x52535452  /* "RSTR" */
#define KOD_RATE            0x52415445  /* "RATE" */
#define KOD_DENY_SKIP       86400       /* ~64 days at 64s poll */
#define KOD_RATE_INIT_SKIP  4           /* initial RATE backoff */
#define KOD_RATE_MAX_SKIP   256         /* max RATE backoff (~4.5hr) */

/*
 * RFC 5905 PHI (max clock skew rate): 15ppm = 15e-6 s/s = 150 100ns-ticks/s.
 * Used to accumulate dispersion over time since sample was taken,
 * matching the pattern in NT5 ntpprov.cpp and hwprov.cpp.
 */
#define PHI_100NS_PER_SEC 150

/* Debug logging to Windows Event Log */
static void dbg_log(const WCHAR *msg) {
    HANDLE hLog = RegisterEventSourceW(NULL, L"NtpFix");
    if (hLog) {
        const WCHAR *msgs[1] = { msg };
        ReportEventW(hLog, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, msgs, NULL);
        DeregisterEventSource(hLog);
    }
}

#define NTPFIX_POLL_SEC     64   /* poll every 64 seconds */
#define NTPFIX_TIMEOUT_MS   5000
#define MAXDISP_100NS       160000000LL  /* 16 seconds in 100ns ticks (RFC 5905 MAXDISP) */

/*
 * System clock precision: ~100ns (FILETIME resolution) = 10^-7 s = 2^-23.
 * Used as floor for delay clamping per RFC 5905 Section 8.
 */
#define SYS_PRECISION_100NS 1  /* 100ns, our minimum measurable unit */

/* ================================================================
 * NTP query - the whole point of this DLL
 *
 * Sends NTP request from an EPHEMERAL source port (not 123).
 * Returns the clock offset in 100ns units, or 0 on failure.
 * ================================================================ */

static BOOL ntp_query(const char *server_ip, int server_idx,
                      __int64 *out_offset, __int64 *out_delay,
                      __int64 *out_dispersion, BYTE *out_stratum,
                      DWORD *out_refid, BYTE *out_leap) {
    SOCKET sock;
    struct sockaddr_in server;
    NtpPacket req, resp;
    FILETIME ft1, ft4;
    __int64 t1, t2, t3, t4, delay, rtt;
    __int64 server_precision_100ns;
    int len;
    DWORD timeout = NTPFIX_TIMEOUT_MS;
    HCRYPTPROV hProv = 0;

    /* Create UDP socket - NO bind to port 123! OS picks ephemeral port */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return FALSE;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons(123);
    inet_pton(AF_INET, server_ip, &server.sin_addr);

    /* Build NTP client request: LI=0, VN=4, Mode=3 (client) */
    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23;

    /* Set random transmit timestamp as nonce for origin timestamp matching
       (anti-spoofing, per RFC 5905 Section 8 and draft-ietf-ntp-data-minimization).
       chrony, systemd-timesyncd, and beevik/ntp all do this.
       Abort if RNG fails - never send with a predictable nonce. */
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT)) {
        closesocket(sock);
        dbg_log(L"CryptAcquireContext failed - aborting query");
        return FALSE;
    }
    CryptGenRandom(hProv, 4, (BYTE *)&req.tx_ts_sec);
    CryptGenRandom(hProv, 4, (BYTE *)&req.tx_ts_frac);
    CryptReleaseContext(hProv, 0);

    /* Ensure nonce is not accidentally zero (would weaken anti-spoofing) */
    if (req.tx_ts_sec == 0 && req.tx_ts_frac == 0)
        req.tx_ts_frac = 1;

    /* Record T1 and send */
    GetSystemTimeAsFileTime(&ft1);
    if (sendto(sock, (char *)&req, sizeof(req), 0,
               (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        return FALSE;
    }

    /* Receive response and record T4 */
    len = recv(sock, (char *)&resp, sizeof(resp), 0);
    GetSystemTimeAsFileTime(&ft4);
    closesocket(sock);

    if (len < (int)sizeof(NtpPacket)) return FALSE;

    /* Verify it's a server response (mode 4) */
    if ((resp.li_vn_mode & 0x07) != 4) return FALSE;

    /* Verify origin timestamp matches our nonce FIRST (anti-spoofing).
       This MUST come before KoD handling so spoofed KoD packets are rejected.
       Same order as chrony: test2 (origin match) before KoD processing.
       Prevents CVE-2015-7704 class attacks (spoofed KoD causing sync loss). */
    if (resp.orig_ts_sec != req.tx_ts_sec ||
        resp.orig_ts_frac != req.tx_ts_frac) return FALSE;

    /* KoD handling (RFC 5905 Section 7.4).
       Stratum 0 = Kiss-of-Death. Only process after origin match verified.
       DENY/RSTR: MUST stop sending to this server (RFC 5905 MUST).
       RATE: MUST reduce polling frequency (RFC 5905 MUST). */
    if (resp.stratum == 0) {
        DWORD kod_code = ntohl(resp.ref_id);
        WCHAR kod_msg[128];
        if (kod_code == KOD_DENY || kod_code == KOD_RSTR) {
            g_serverSkip[server_idx] = KOD_DENY_SKIP;
            _snwprintf(kod_msg, 128, L"KoD %c%c%c%c from %hs: server blacklisted",
                       (char)(kod_code >> 24), (char)(kod_code >> 16),
                       (char)(kod_code >> 8), (char)kod_code, server_ip);
            dbg_log(kod_msg);
        } else if (kod_code == KOD_RATE) {
            int cur = g_serverSkip[server_idx];
            g_serverSkip[server_idx] = (cur < KOD_RATE_INIT_SKIP)
                ? KOD_RATE_INIT_SKIP
                : ((cur * 2 > KOD_RATE_MAX_SKIP) ? KOD_RATE_MAX_SKIP : cur * 2);
            _snwprintf(kod_msg, 128, L"KoD RATE from %hs: backing off %d polls",
                       server_ip, g_serverSkip[server_idx]);
            dbg_log(kod_msg);
        }
        return FALSE;
    }

    /* Verify stratum is valid (>15 = reserved/unsync) */
    if (resp.stratum > 15) return FALSE;

    /* Reject unsynchronized servers (leap indicator 3 = NOSYNC).
       RFC 5905 test 6. */
    if (((resp.li_vn_mode >> 6) & 0x03) == 3) return FALSE;

    /* Verify server's transmit timestamp is non-zero (RFC 5905: zero = unknown time) */
    if (resp.tx_ts_sec == 0 && resp.tx_ts_frac == 0) return FALSE;

    /* Root distance sanity check: rootDelay/2 + rootDispersion < MAXDISP (16s).
       RFC 5905 test 7. */
    {
        __int64 root_dist = ntp_short_to_100ns(resp.root_delay) / 2 +
                            ntp_short_to_100ns(resp.root_dispersion);
        if (root_dist >= MAXDISP_100NS) return FALSE;
    }

    /* Convert timestamps to 100ns (NTP epoch) */
    t1 = ft_to_ntp100ns(ft1);
    t2 = ntp_to_100ns(resp.recv_ts_sec, resp.recv_ts_frac);
    t3 = ntp_to_100ns(resp.tx_ts_sec, resp.tx_ts_frac);
    t4 = ft_to_ntp100ns(ft4);
    rtt = t4 - t1;

    /* NTP offset: ((T2-T1) + (T3-T4)) / 2 */
    *out_offset = ((t2 - t1) + (t3 - t4)) / 2;

    /* NTP delay: (T4-T1) - (T3-T2), clamped to system precision.
       RFC 5905 Section 8: "the value of delta should be clamped not less than s.rho" */
    delay = rtt - (t3 - t2);
    if (delay < SYS_PRECISION_100NS) delay = SYS_PRECISION_100NS;
    *out_delay = delay;

    /* Peer dispersion per RFC 5905: epsilon = r.rho + s.rho + PHI * (T4-T1)
       r.rho = server precision (2^precision field, converted to 100ns)
       s.rho = our precision (SYS_PRECISION_100NS)
       PHI * (T4-T1) = clock drift during round trip */
    {
        /* Convert server precision field (log2 seconds) to 100ns ticks.
           Typical values: -20 (~1us = 10 ticks), -24 (~60ns = 1 tick). */
        signed char sprec = (signed char)resp.precision;
        if (sprec >= 0) {
            server_precision_100ns = (sprec < 7)
                ? ((__int64)1 << sprec) * 10000000LL
                : MAXDISP_100NS; /* clamp absurd values */
        } else {
            int neg = -sprec;
            server_precision_100ns = (neg < 24)
                ? 10000000LL >> neg
                : 1; /* sub-tick: floor at 1 */
        }
        if (server_precision_100ns < 1) server_precision_100ns = 1;
    }
    *out_dispersion = server_precision_100ns + SYS_PRECISION_100NS +
                      (rtt * PHI_100NS_PER_SEC) / 10000000LL;

    *out_stratum    = resp.stratum;
    *out_refid      = resp.ref_id; /* already in network byte order = NTP format */
    *out_leap       = (resp.li_vn_mode >> 6) & 0x03;

    return TRUE;
}

/* ================================================================
 * Polling thread
 * ================================================================ */

static DWORD WINAPI PollThread(LPVOID param) {
    WSADATA wsa;
    (void)param;

    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Poll immediately on start, then every NTPFIX_POLL_SEC seconds */
    while (1) {
        __int64 offset, delay, dispersion;
        BYTE    stratum, leap;
        DWORD   refid;
        int     idx, attempts;
        const char *server_ip = NULL;

        /* Pick next available server, skipping KoD-blacklisted ones.
           Decrement skip counters as we scan. */
        for (attempts = 0; attempts < (int)NUM_SERVERS; attempts++) {
            idx = g_serverIdx % NUM_SERVERS;
            g_serverIdx = (g_serverIdx + 1) % (int)(NUM_SERVERS * 1000);
            if (g_serverSkip[idx] > 0) {
                g_serverSkip[idx]--;
                continue;
            }
            server_ip = g_servers[idx];
            break;
        }
        if (!server_ip) {
            dbg_log(L"All servers skipped (KoD backoff), waiting");
            goto poll_wait;
        }

        if (ntp_query(server_ip, idx, &offset, &delay, &dispersion,
                      &stratum, &refid, &leap)) {
            WCHAR msg[256];
            _snwprintf(msg, 256,
                L"NTP OK: offset=%I64d delay=%I64d disp=%I64d stratum=%d refid=0x%08X",
                offset, delay, dispersion, stratum, ntohl(refid));
            dbg_log(msg);

            EnterCriticalSection(&g_cs);

            memset(&g_sample, 0, sizeof(g_sample));
            g_sample.dwSize       = sizeof(TimeSample);
            g_sample.dwRefid      = refid;
            g_sample.toOffset     = offset;
            g_sample.toDelay      = delay;
            g_sample.nStratum     = stratum;
            g_sample.nLeapFlags   = leap;
            g_sample.dwTSFlags    = 0;
            wcscpy(g_sample.wszUniqueName, L"NtpFix:time.google.com");

            /* Store base dispersion; skew accumulation added at GetSamples time */
            g_baseDispersion = (unsigned __int64)(dispersion > 0 ? dispersion : 1);
            g_sample.tpDispersion = g_baseDispersion;

            /* Capture tick count and phase offset at measurement time,
               matching NT5 ntpprov.cpp and XenTimeProvider behavior */
            g_sc.pfnGetTimeSysInfo(TSI_TickCount,   &g_sample.nSysTickCount);
            g_sc.pfnGetTimeSysInfo(TSI_PhaseOffset,  &g_sample.nSysPhaseOffset);
            g_sampleTickCount = g_sample.nSysTickCount;

            g_hasSample = TRUE;

            LeaveCriticalSection(&g_cs);

            /* Tell w32time we have a fresh sample */
            dbg_log(L"Calling AlertSamplesAvail");
            g_sc.pfnAlertSamplesAvail();
        } else {
            dbg_log(L"NTP query failed (timeout or bad response)");
        }

    poll_wait:
        /* Wait for stop event or poll interval */
        if (WaitForSingleObject(g_hStopEvent,
                                NTPFIX_POLL_SEC * 1000) != WAIT_TIMEOUT) {
            break; /* stop event signaled */
        }
    }

    WSACleanup();
    return 0;
}

/* ================================================================
 * Time Provider exports
 * ================================================================ */

__declspec(dllexport)
HRESULT __stdcall TimeProvOpen(WCHAR *wszName, TimeProvSysCallbacks *pSysCallbacks,
                               TimeProvHandle *phTimeProv) {
    (void)wszName;

    /* Save system callbacks */
    CopyMemory(&g_sc, pSysCallbacks, sizeof(TimeProvSysCallbacks));

    InitializeCriticalSection(&g_cs);
    g_hasSample = FALSE;

    /* Create stop event and start polling thread */
    g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_hThread = CreateThread(NULL, 0, PollThread, NULL, 0, NULL);

    *phTimeProv = (TimeProvHandle)1;

    dbg_log(L"TimeProvOpen: NtpFix loaded, poll thread started");
    return S_OK;
}

__declspec(dllexport)
HRESULT __stdcall TimeProvCommand(TimeProvHandle hTimeProv, TimeProvCmd eCmd,
                                  void *pvArgs) {
    (void)hTimeProv;

    switch (eCmd) {
    case TPC_GetSamples:
        if (pvArgs) {
            TpcGetSamplesArgs *pArgs = (TpcGetSamplesArgs *)pvArgs;
            EnterCriticalSection(&g_cs);
            if (g_hasSample && pArgs->pbSampleBuf &&
                pArgs->cbSampleBuf >= sizeof(TimeSample)) {
                /*
                 * Accumulate dispersion based on time elapsed since
                 * the sample was taken, per RFC 5905 / NT5 hwprov.cpp:
                 *   dispersion += elapsed * PHI
                 * where PHI = 15ppm (max assumed clock skew rate).
                 */
                unsigned __int64 nowTick = 0;
                g_sc.pfnGetTimeSysInfo(TSI_TickCount, &nowTick);
                if (nowTick > g_sampleTickCount) {
                    unsigned __int64 elapsed = nowTick - g_sampleTickCount;
                    /* elapsed is in 100ns ticks; PHI = 150 per 10^7 ticks (1 second) */
                    unsigned __int64 skew = (elapsed * PHI_100NS_PER_SEC) / 10000000ULL;
                    unsigned __int64 disp = g_baseDispersion + skew;
                    /* Cap at MAXDISP (16s) - RFC 5905: samples with
                       dispersion >= MAXDISP are considered invalid */
                    g_sample.tpDispersion = (disp < (unsigned __int64)MAXDISP_100NS)
                        ? disp : (unsigned __int64)MAXDISP_100NS;
                }

                /* Copy sample into w32time's pre-allocated buffer */
                CopyMemory(pArgs->pbSampleBuf, &g_sample, sizeof(TimeSample));
                pArgs->dwSamplesReturned  = 1;
                pArgs->dwSamplesAvailable = 1;

                dbg_log(L"TPC_GetSamples: returned 1 sample");
            } else {
                pArgs->dwSamplesReturned  = 0;
                pArgs->dwSamplesAvailable = 0;
                dbg_log(g_hasSample
                    ? L"TPC_GetSamples: buffer too small or NULL"
                    : L"TPC_GetSamples: no sample available yet");
            }
            LeaveCriticalSection(&g_cs);
        }
        break;

    case TPC_TimeJumped:
        EnterCriticalSection(&g_cs);
        g_hasSample = FALSE;
        LeaveCriticalSection(&g_cs);
        break;

    case TPC_PollIntervalChanged:
    case TPC_UpdateConfig:
    case TPC_NetTopoChange:
    case TPC_Query:
        break;

    case TPC_Shutdown:
        break;
    }
    return S_OK;
}

__declspec(dllexport)
HRESULT __stdcall TimeProvClose(TimeProvHandle hTimeProv) {
    (void)hTimeProv;

    /* Signal the polling thread to stop */
    if (g_hStopEvent) SetEvent(g_hStopEvent);
    if (g_hThread) {
        WaitForSingleObject(g_hThread, 10000);
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }
    if (g_hStopEvent) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_cs);
    return S_OK;
}

/* ================================================================
 * DLL entry point
 * ================================================================ */

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        GetModuleFileNameW(hInstDll, g_wzDllPath, MAX_PATH);
    }
    return TRUE;
}

/* ================================================================
 * Registration helpers (call via rundll32)
 *
 *   rundll32 ntpfix.dll,Register
 *   rundll32 ntpfix.dll,Deregister
 * ================================================================ */

#define NTPFIX_REG_KEY L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpFix"

__declspec(dllexport)
void CALLBACK Register(HWND hWnd, HINSTANCE hInst, LPSTR pszCmdLine, int nCmdShow) {
    HKEY hk = NULL;
    DWORD dwOne = 1;
    (void)hWnd; (void)hInst; (void)pszCmdLine; (void)nCmdShow;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, NTPFIX_REG_KEY, 0, NULL, 0,
                        KEY_ALL_ACCESS, NULL, &hk, NULL) != ERROR_SUCCESS) {
        MessageBoxW(NULL, L"Failed to create registry key. Run as Administrator.",
                    L"NtpFix", MB_ICONERROR);
        return;
    }

    /* DllName: path to this DLL */
    RegSetValueExW(hk, L"DllName", 0, REG_SZ,
                   (LPBYTE)g_wzDllPath,
                   (DWORD)(wcslen(g_wzDllPath) + 1) * sizeof(WCHAR));

    /* Enabled: 1 */
    RegSetValueExW(hk, L"Enabled", 0, REG_DWORD,
                   (LPBYTE)&dwOne, sizeof(DWORD));

    /* InputProvider: 1 (we provide time samples) */
    RegSetValueExW(hk, L"InputProvider", 0, REG_DWORD,
                   (LPBYTE)&dwOne, sizeof(DWORD));

    RegCloseKey(hk);

    MessageBoxW(NULL,
        L"NtpFix registered successfully!\n\n"
        L"Now disable the built-in NTP client and restart w32time:\n\n"
        L"  reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\"
        L"TimeProviders\\NtpClient\" /v Enabled /t REG_DWORD /d 0 /f\n"
        L"  net stop w32time && net start w32time",
        L"NtpFix", MB_ICONINFORMATION);
}

__declspec(dllexport)
void CALLBACK Deregister(HWND hWnd, HINSTANCE hInst, LPSTR pszCmdLine, int nCmdShow) {
    (void)hWnd; (void)hInst; (void)pszCmdLine; (void)nCmdShow;

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, NTPFIX_REG_KEY);

    MessageBoxW(NULL,
        L"NtpFix deregistered.\n\n"
        L"Re-enable the built-in NTP client:\n\n"
        L"  reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\"
        L"TimeProviders\\NtpClient\" /v Enabled /t REG_DWORD /d 1 /f\n"
        L"  net stop w32time && net start w32time",
        L"NtpFix", MB_ICONINFORMATION);
}
