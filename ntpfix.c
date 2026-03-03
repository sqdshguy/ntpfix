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
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

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
static TpcGetSamplesArgs    g_sampleArgs;
static WCHAR                g_wzDllPath[MAX_PATH];
static int                  g_serverIdx  = 0;

#define NTPFIX_POLL_SEC     64   /* poll every 64 seconds */
#define NTPFIX_TIMEOUT_MS   5000

/* ================================================================
 * NTP query - the whole point of this DLL
 *
 * Sends NTP request from an EPHEMERAL source port (not 123).
 * Returns the clock offset in 100ns units, or 0 on failure.
 * ================================================================ */

static BOOL ntp_query(__int64 *out_offset, __int64 *out_delay,
                      __int64 *out_dispersion, BYTE *out_stratum,
                      DWORD *out_refid, BYTE *out_leap) {
    SOCKET sock;
    struct sockaddr_in server;
    NtpPacket req, resp;
    FILETIME ft1, ft4;
    __int64 t1, t2, t3, t4;
    int len;
    DWORD timeout = NTPFIX_TIMEOUT_MS;

    /* Create UDP socket - NO bind to port 123! OS picks ephemeral port */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return FALSE;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    /* Pick next server (round-robin) */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons(123);
    inet_pton(AF_INET, g_servers[g_serverIdx % NUM_SERVERS], &server.sin_addr);
    g_serverIdx++;

    /* Build NTP client request: LI=0, VN=4, Mode=3 (client) */
    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23;

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

    /* Verify stratum is valid */
    if (resp.stratum == 0 || resp.stratum > 15) return FALSE;

    /* Convert timestamps to 100ns (NTP epoch) */
    t1 = ft_to_ntp100ns(ft1);
    t2 = ntp_to_100ns(resp.recv_ts_sec, resp.recv_ts_frac);
    t3 = ntp_to_100ns(resp.tx_ts_sec, resp.tx_ts_frac);
    t4 = ft_to_ntp100ns(ft4);

    /* NTP offset and delay formulas */
    *out_offset     = ((t2 - t1) + (t3 - t4)) / 2;
    *out_delay      = (t4 - t1) - (t3 - t2);
    *out_dispersion = ntp_short_to_100ns(resp.root_dispersion) +
                      (t4 - t1) / 2; /* add half RTT as dispersion */
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

        if (ntp_query(&offset, &delay, &dispersion, &stratum, &refid, &leap)) {
            EnterCriticalSection(&g_cs);

            memset(&g_sample, 0, sizeof(g_sample));
            g_sample.dwSize       = sizeof(TimeSample);
            g_sample.dwRefid      = refid;
            g_sample.toOffset     = offset;
            g_sample.toDelay      = delay;
            g_sample.tpDispersion = (unsigned __int64)(dispersion > 0 ? dispersion : 1);
            g_sample.nStratum     = stratum;
            g_sample.nLeapFlags   = leap;
            g_sample.dwTSFlags    = 0;

            /* These opaque values are required by w32time */
            g_sc.pfnGetTimeSysInfo(TSI_TickCount,   &g_sample.nSysTickCount);
            g_sc.pfnGetTimeSysInfo(TSI_PhaseOffset,  &g_sample.nSysPhaseOffset);

            wcscpy(g_sample.wszUniqueName, L"NtpFix:time.google.com");

            /* Set up the sample args for TPC_GetSamples */
            g_sampleArgs.pbSampleBuf      = (BYTE *)&g_sample;
            g_sampleArgs.cbSampleBuf      = sizeof(TimeSample);
            g_sampleArgs.dwSamplesReturned  = 1;
            g_sampleArgs.dwSamplesAvailable = 1;
            g_hasSample = TRUE;

            LeaveCriticalSection(&g_cs);

            /* Tell w32time we have a fresh sample */
            g_sc.pfnAlertSamplesAvail();
        }

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
    return S_OK;
}

__declspec(dllexport)
HRESULT __stdcall TimeProvCommand(TimeProvHandle hTimeProv, TimeProvCmd eCmd,
                                  void *pvArgs) {
    (void)hTimeProv;

    switch (eCmd) {
    case TPC_GetSamples:
        EnterCriticalSection(&g_cs);
        if (g_hasSample && pvArgs) {
            CopyMemory(pvArgs, &g_sampleArgs, sizeof(TpcGetSamplesArgs));
        } else if (pvArgs) {
            TpcGetSamplesArgs *args = (TpcGetSamplesArgs *)pvArgs;
            args->dwSamplesReturned  = 0;
            args->dwSamplesAvailable = 0;
        }
        LeaveCriticalSection(&g_cs);
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
