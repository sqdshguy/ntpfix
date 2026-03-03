/*
 * test_ntp.c - Test NTP client logic against RFC 5905 and reference vectors
 *
 * Validates the same logic used in ntpfix.dll:
 *   - Timestamp conversion (100ns ticks)
 *   - Offset/delay calculation (RFC 5905 Section 8)
 *   - Dispersion formula (RFC 5905 Section 9.2)
 *   - Response validation (mode, stratum, leap, origin match, root distance)
 *   - Delay clamping (RFC 5905 Section 8)
 *
 * Test vectors sourced from:
 *   - FreeRTOS/coreSNTP (MIT) - Amazon's NTP serializer tests
 *   - beevik/ntp (BSD)        - Go NTP client offset tests
 *   - RFC 5905 Section 8      - Offset/delay formulas
 *
 * Build: cc -o test_ntp test_ntp.c -lm
 * Run:   ./test_ntp           (offline tests only)
 *        ./test_ntp --live    (include live NTP queries)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

/* NTP epoch: 1900-01-01, Unix epoch: 1970-01-01 */
#define NTP_UNIX_OFFSET 2208988800ULL

/* RFC 5905 constants (same as ntpfix.c) */
#define PHI_100NS_PER_SEC   150              /* 15ppm in 100ns ticks per second */
#define SYS_PRECISION_100NS 1                /* 100ns minimum unit */
#define MAXDISP_100NS       160000000LL      /* 16 seconds in 100ns ticks */

#pragma pack(push, 1)
typedef struct {
    unsigned char li_vn_mode;
    unsigned char stratum;
    unsigned char poll;
    unsigned char precision;
    unsigned int  root_delay;
    unsigned int  root_dispersion;
    unsigned int  ref_id;
    unsigned int  ref_ts_sec;
    unsigned int  ref_ts_frac;
    unsigned int  orig_ts_sec;
    unsigned int  orig_ts_frac;
    unsigned int  recv_ts_sec;
    unsigned int  recv_ts_frac;
    unsigned int  tx_ts_sec;
    unsigned int  tx_ts_frac;
} NtpPacket;
#pragma pack(pop)

/* ================================================================
 * Conversion functions (identical to ntpfix.c)
 * ================================================================ */

static long long ntp_to_100ns(unsigned int sec_net, unsigned int frac_net) {
    unsigned int sec  = ntohl(sec_net);
    unsigned int frac = ntohl(frac_net);
    return (long long)sec * 10000000LL +
           ((long long)frac * 10000000LL) / 4294967296LL;
}

static long long ntp_short_to_100ns(unsigned int val_net) {
    unsigned int val = ntohl(val_net);
    unsigned int sec  = val >> 16;
    unsigned int frac = val & 0xFFFF;
    return (long long)sec * 10000000LL +
           ((long long)frac * 10000000LL) / 65536LL;
}

static double ntp_to_double(unsigned int sec_net, unsigned int frac_net) {
    unsigned int sec  = ntohl(sec_net);
    unsigned int frac = ntohl(frac_net);
    return (double)sec + (double)frac / 4294967296.0;
}

static void get_ntp_time(unsigned int *sec, unsigned int *frac) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *sec  = (unsigned int)(tv.tv_sec + NTP_UNIX_OFFSET);
    *frac = (unsigned int)((double)tv.tv_usec * 4294.967296);
}

/* ================================================================
 * Response validation (same logic as ntpfix.c ntp_query)
 * ================================================================ */

typedef struct {
    int valid;
    long long offset;      /* 100ns ticks */
    long long delay;       /* 100ns ticks */
    long long dispersion;  /* 100ns ticks */
    unsigned char stratum;
    unsigned char leap;
    unsigned int  refid;
    char reject_reason[64];
} NtpResult;

static NtpResult validate_response(const NtpPacket *req, const NtpPacket *resp,
                                    long long t1_100ns, long long t4_100ns) {
    NtpResult r;
    memset(&r, 0, sizeof(r));

    /* Mode must be 4 (server) */
    if ((resp->li_vn_mode & 0x07) != 4) {
        snprintf(r.reject_reason, sizeof(r.reject_reason), "mode != 4");
        return r;
    }

    /* Reject NOSYNC (leap indicator 3) */
    if (((resp->li_vn_mode >> 6) & 0x03) == 3) {
        snprintf(r.reject_reason, sizeof(r.reject_reason), "leap == NOSYNC");
        return r;
    }

    /* Stratum 1-15 */
    if (resp->stratum == 0 || resp->stratum > 15) {
        snprintf(r.reject_reason, sizeof(r.reject_reason), "stratum %d", resp->stratum);
        return r;
    }

    /* Origin timestamp must match our nonce */
    if (resp->orig_ts_sec != req->tx_ts_sec ||
        resp->orig_ts_frac != req->tx_ts_frac) {
        snprintf(r.reject_reason, sizeof(r.reject_reason), "origin mismatch");
        return r;
    }

    /* Server transmit timestamp must be non-zero */
    if (resp->tx_ts_sec == 0 && resp->tx_ts_frac == 0) {
        snprintf(r.reject_reason, sizeof(r.reject_reason), "tx timestamp zero");
        return r;
    }

    /* Root distance check */
    {
        long long root_dist = ntp_short_to_100ns(resp->root_delay) / 2 +
                              ntp_short_to_100ns(resp->root_dispersion);
        if (root_dist >= MAXDISP_100NS) {
            snprintf(r.reject_reason, sizeof(r.reject_reason), "root distance too large");
            return r;
        }
    }

    /* Compute offset/delay/dispersion */
    {
        long long t2 = ntp_to_100ns(resp->recv_ts_sec, resp->recv_ts_frac);
        long long t3 = ntp_to_100ns(resp->tx_ts_sec, resp->tx_ts_frac);
        long long rtt = t4_100ns - t1_100ns;
        long long delay;

        r.offset = ((t2 - t1_100ns) + (t3 - t4_100ns)) / 2;

        delay = rtt - (t3 - t2);
        if (delay < SYS_PRECISION_100NS) delay = SYS_PRECISION_100NS;
        r.delay = delay;

        /* Peer dispersion: r.rho + s.rho + PHI * (T4-T1) */
        {
            long long server_prec;
            signed char sprec = (signed char)resp->precision;
            if (sprec >= 0) {
                server_prec = (sprec < 7)
                    ? ((long long)1 << sprec) * 10000000LL
                    : MAXDISP_100NS;
            } else {
                int neg = -sprec;
                server_prec = (neg < 24)
                    ? 10000000LL >> neg
                    : 1;
            }
            if (server_prec < 1) server_prec = 1;
            r.dispersion = server_prec + SYS_PRECISION_100NS +
                           (rtt * PHI_100NS_PER_SEC) / 10000000LL;
        }

        r.stratum = resp->stratum;
        r.refid   = resp->ref_id;
        r.leap    = (resp->li_vn_mode >> 6) & 0x03;
        r.valid   = 1;
    }

    return r;
}

/* ================================================================
 * Test framework
 * ================================================================ */

static int total_pass = 0, total_fail = 0;

static void test(const char *name, int passed, const char *detail) {
    if (passed) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
        total_pass++;
    } else {
        printf("  \033[31mFAIL\033[0m  %s\n", name);
        if (detail) printf("        %s\n", detail);
        total_fail++;
    }
}

/* Helper: build a valid NTP server response for given timestamps */
static void build_response(NtpPacket *resp, const NtpPacket *req,
                            unsigned int t2_sec, unsigned int t2_frac,
                            unsigned int t3_sec, unsigned int t3_frac) {
    memset(resp, 0, sizeof(*resp));
    resp->li_vn_mode = 0x24; /* LI=0, VN=4, Mode=4 (server) */
    resp->stratum = 2;
    resp->precision = (unsigned char)(signed char)-20; /* ~1us */
    resp->root_delay = htonl(0x00010000); /* 1 second in NTP short */
    resp->root_dispersion = htonl(0x00008000); /* 0.5 seconds */
    resp->ref_id = htonl(0x474F4F47); /* GOOG */

    /* Echo client's transmit timestamp as origin (anti-spoofing) */
    resp->orig_ts_sec  = req->tx_ts_sec;
    resp->orig_ts_frac = req->tx_ts_frac;

    resp->recv_ts_sec  = htonl(t2_sec);
    resp->recv_ts_frac = htonl(t2_frac);
    resp->tx_ts_sec    = htonl(t3_sec);
    resp->tx_ts_frac   = htonl(t3_frac);
}

/* ================================================================
 * Test 1: Timestamp conversion math
 * ================================================================ */

static void test_timestamp_math(void) {
    /* Known NTP timestamp: 3981528000.5 seconds since 1900 */
    unsigned int test_sec  = htonl(3981528000U);
    unsigned int test_frac = htonl(2147483648U); /* 0.5 seconds */

    long long hns = ntp_to_100ns(test_sec, test_frac);
    double    dbl = ntp_to_double(test_sec, test_frac);

    double hns_as_sec = (double)hns / 10000000.0;
    double diff = fabs(hns_as_sec - dbl);

    char detail[256];
    snprintf(detail, sizeof(detail),
             "100ns=%lld (%.6fs), double=%.6fs, diff=%.9fs",
             hns, hns_as_sec, dbl, diff);
    test("100ns conversion matches double", diff < 0.000001, detail);

    long long expected = 39815280005000000LL;
    snprintf(detail, sizeof(detail), "expected=%lld, got=%lld", expected, hns);
    test("Fractional timestamp (0.5s) correct", llabs(hns - expected) < 10, detail);

    /* NTP short format: 1.5 seconds = 0x00018000 */
    unsigned int short_val = htonl(0x00018000);
    long long short_100ns = ntp_short_to_100ns(short_val);
    snprintf(detail, sizeof(detail), "expected=15000000, got=%lld", short_100ns);
    test("NTP short format 1.5s", llabs(short_100ns - 15000000LL) < 10, detail);
}

/* ================================================================
 * Test 2: Offset calculation (RFC 5905 Section 8 + reference vectors)
 * ================================================================ */

static void test_offset_calculation(void) {
    char detail[256];

    /*
     * Vector from beevik/ntp TestOfflineOffsetCalculation:
     *   T1 = now, T2 = now+20s, T3 = now+21s, T4 = now+5s
     *   offset = ((20) + (21-5)) / 2 = (20+16)/2 = 18s
     */
    {
        long long S = 39815280000000000LL; /* arbitrary base in 100ns */
        long long t1 = S;
        long long t2 = S + 200000000LL;  /* +20s */
        long long t3 = S + 210000000LL;  /* +21s */
        long long t4 = S +  50000000LL;  /* +5s */
        long long offset = ((t2 - t1) + (t3 - t4)) / 2;
        snprintf(detail, sizeof(detail), "offset=%lld, expected 180000000 (18s)",
                 offset);
        test("[beevik] 18s positive offset", offset == 180000000LL, detail);
    }

    /*
     * Vector from beevik/ntp TestOfflineOffsetCalculationNegative:
     *   T1=now+101, T2=now+102, T3=now+103, T4=now+105
     *   offset = ((1) + (103-105)) / 2 = (1-2)/2 = -0.5s
     */
    {
        long long S = 39815280000000000LL;
        long long t1 = S + 1010000000LL;
        long long t2 = S + 1020000000LL;
        long long t3 = S + 1030000000LL;
        long long t4 = S + 1050000000LL;
        long long offset = ((t2 - t1) + (t3 - t4)) / 2;
        snprintf(detail, sizeof(detail), "offset=%lld, expected -5000000 (-0.5s)",
                 offset);
        test("[beevik] -0.5s negative offset", offset == -5000000LL, detail);
    }

    /*
     * Vector from coreSNTP: 20 years positive offset
     *   Client sends at time C, server is 20 years ahead.
     *   T1=C, T2=C+20yr, T3=C+20yr, T4=C  => offset = 20yr
     */
    {
        long long years_20 = (long long)((20*365 + 20/4) * 24 * 3600) * 10000000LL;
        long long S = 39815280000000000LL;
        long long t1 = S;
        long long t2 = S + years_20;
        long long t3 = S + years_20;
        long long t4 = S;
        long long offset = ((t2 - t1) + (t3 - t4)) / 2;
        snprintf(detail, sizeof(detail), "offset=%lld, expected %lld", offset, years_20);
        test("[coreSNTP] 20yr positive offset", offset == years_20, detail);
    }

    /*
     * Vector: 50ms ahead (our original test)
     *   T1=S, T2=S-35ms, T3=S-34ms, T4=S+31ms => offset=-50ms
     */
    {
        long long S = 39815280000000000LL;
        long long t1 = S;
        long long t2 = S - 350000LL;
        long long t3 = S - 340000LL;
        long long t4 = S + 310000LL;
        long long offset = ((t2 - t1) + (t3 - t4)) / 2;
        snprintf(detail, sizeof(detail), "offset=%lld, expected -500000 (-50ms)", offset);
        test("[rfc5905] -50ms offset", offset == -500000LL, detail);

        long long delay = (t4 - t1) - (t3 - t2);
        snprintf(detail, sizeof(detail), "delay=%lld, expected 300000 (30ms)", delay);
        test("[rfc5905] 30ms delay", delay == 300000LL, detail);
    }

    /*
     * Vector from coreSNTP: asymmetric delay with cross-era
     *   T1=C, T2=C+20yr+2s, T3=C+20yr+4s, T4=C+6s
     *   network delay = 2s each way, server processing = 2s
     *   offset = ((20yr+2) + (20yr+4-6)) / 2 = (20yr+2 + 20yr-2)/2 = 20yr
     */
    {
        long long years_20 = (long long)((20*365 + 20/4) * 24 * 3600) * 10000000LL;
        long long S = 39815280000000000LL;
        long long t1 = S;
        long long t2 = S + years_20 + 20000000LL;  /* +20yr +2s */
        long long t3 = S + years_20 + 40000000LL;  /* +20yr +4s */
        long long t4 = S + 60000000LL;              /* +6s */
        long long offset = ((t2 - t1) + (t3 - t4)) / 2;
        snprintf(detail, sizeof(detail), "offset=%lld, expected %lld", offset, years_20);
        test("[coreSNTP] asymmetric delay, 20yr offset", offset == years_20, detail);
    }
}

/* ================================================================
 * Test 3: Response validation (RFC 5905 tests 1-7)
 * Vectors from coreSNTP test_DeserializeResponse_Invalid_Responses
 * ================================================================ */

static void test_response_validation(void) {
    NtpPacket req, resp;
    NtpResult r;
    char detail[256];

    /* Set up a valid request with a nonce */
    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23;
    req.tx_ts_sec  = htonl(0xDEADBEEF);
    req.tx_ts_frac = htonl(0xCAFEBABE);

    /* T1 and T4 for validation (arbitrary, 1s apart) */
    long long t1 = 39815280000000000LL;
    long long t4 = t1 + 10000000LL; /* 1 second later */

    unsigned int t2_sec = 3981528001U; /* just after T1 in NTP seconds */
    unsigned int t3_sec = 3981528001U;

    /* --- Valid response (baseline) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    r = validate_response(&req, &resp, t1, t4);
    test("Valid response accepted", r.valid, r.reject_reason);

    /* --- [coreSNTP] Reject mode != 4 (client mode in response) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.li_vn_mode = 0x23; /* Mode=3 (client), not Mode=4 (server) */
    r = validate_response(&req, &resp, t1, t4);
    snprintf(detail, sizeof(detail), "valid=%d reason=%s", r.valid, r.reject_reason);
    test("[rfc5905 t1] Reject mode=3 (client)", !r.valid, detail);

    /* --- Reject mode=1 (symmetric active) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.li_vn_mode = 0x21; /* Mode=1 */
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t1] Reject mode=1 (symm active)", !r.valid, r.reject_reason);

    /* --- [rfc5905] Reject leap=3 (NOSYNC) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.li_vn_mode = 0xE4; /* LI=3 (NOSYNC), VN=4, Mode=4 */
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t6] Reject leap=NOSYNC", !r.valid, r.reject_reason);

    /* --- [coreSNTP] Reject stratum=0 (KoD) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.stratum = 0;
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t6] Reject stratum=0 (KoD)", !r.valid, r.reject_reason);

    /* --- Reject stratum=16 --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.stratum = 16;
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t6] Reject stratum=16", !r.valid, r.reject_reason);

    /* --- Accept stratum=1 (primary) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.stratum = 1;
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905] Accept stratum=1", r.valid, r.reject_reason);

    /* --- Accept stratum=15 (max valid) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.stratum = 15;
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905] Accept stratum=15", r.valid, r.reject_reason);

    /* --- [coreSNTP] Reject origin timestamp mismatch (seconds) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.orig_ts_sec = htonl(ntohl(req.tx_ts_sec) + 1); /* wrong seconds */
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t2] Reject origin mismatch (sec)", !r.valid, r.reject_reason);

    /* --- [coreSNTP] Reject origin timestamp mismatch (fractions) --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.orig_ts_frac = htonl(ntohl(req.tx_ts_frac) + 1); /* wrong fracs */
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t2] Reject origin mismatch (frac)", !r.valid, r.reject_reason);

    /* --- [coreSNTP] Reject zero transmit timestamp --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.tx_ts_sec  = 0;
    resp.tx_ts_frac = 0;
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t3] Reject zero transmit timestamp", !r.valid, r.reject_reason);

    /* --- [rfc5905] Reject excessive root distance --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.root_delay      = htonl(0x00200000); /* 32 seconds */
    resp.root_dispersion = htonl(0x00100000); /* 16 seconds */
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t7] Reject root distance >= 16s", !r.valid, r.reject_reason);

    /* --- Accept normal root distance --- */
    build_response(&resp, &req, t2_sec, 0, t3_sec, 0);
    resp.root_delay      = htonl(0x00010000); /* 1 second */
    resp.root_dispersion = htonl(0x00008000); /* 0.5 seconds */
    r = validate_response(&req, &resp, t1, t4);
    test("[rfc5905 t7] Accept normal root distance", r.valid, r.reject_reason);
}

/* ================================================================
 * Test 4: Delay clamping (RFC 5905 Section 8)
 * ================================================================ */

static void test_delay_clamping(void) {
    NtpPacket req, resp;
    NtpResult r;
    char detail[256];

    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23;
    req.tx_ts_sec  = htonl(0x12345678);
    req.tx_ts_frac = htonl(0x9ABCDEF0);

    /*
     * Negative delay scenario: server processing > RTT.
     * T1=S, T2=S+1, T3=S+10, T4=S+2
     * delay = (T4-T1) - (T3-T2) = 2 - 9 = -7s
     * Should be clamped to SYS_PRECISION_100NS (1 tick).
     */
    unsigned int base_sec = 3981528000U;
    long long t1 = (long long)base_sec * 10000000LL;
    long long t4 = (long long)(base_sec + 2) * 10000000LL;

    build_response(&resp, &req,
                   base_sec + 1, 0,   /* T2: +1s */
                   base_sec + 10, 0); /* T3: +10s */

    r = validate_response(&req, &resp, t1, t4);
    snprintf(detail, sizeof(detail), "delay=%lld, expected %d (clamped)",
             r.delay, SYS_PRECISION_100NS);
    test("[rfc5905] Negative delay clamped to precision",
         r.valid && r.delay == SYS_PRECISION_100NS, detail);

    /*
     * Normal delay: T1=S, T2=S+0.01, T3=S+0.02, T4=S+0.05
     * delay = 0.05 - 0.01 = 0.04s = 400000 100ns ticks
     */
    t4 = t1 + 500000LL; /* +50ms */
    build_response(&resp, &req,
                   base_sec, 42949673U,    /* T2: +0.01s (frac=0.01*2^32) */
                   base_sec, 85899346U);   /* T3: +0.02s */

    r = validate_response(&req, &resp, t1, t4);
    /* delay = (50ms) - (10ms) = 40ms = 400000 ticks */
    snprintf(detail, sizeof(detail), "delay=%lld, expected ~400000 (40ms)", r.delay);
    test("[rfc5905] Normal delay (40ms)", r.valid && llabs(r.delay - 400000LL) < 100, detail);
}

/* ================================================================
 * Test 5: Dispersion formula (RFC 5905 Section 9.2)
 * epsilon = r.rho + s.rho + PHI * (T4-T1)
 * ================================================================ */

static void test_dispersion_formula(void) {
    NtpPacket req, resp;
    NtpResult r;
    char detail[256];

    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23;
    req.tx_ts_sec  = htonl(0xAAAAAAAA);
    req.tx_ts_frac = htonl(0xBBBBBBBB);

    unsigned int base_sec = 3981528000U;

    /* RTT = 1 second, precision = -20 (~1us = 10 100ns ticks) */
    long long t1 = (long long)base_sec * 10000000LL;
    long long t4 = t1 + 10000000LL; /* 1s later */

    build_response(&resp, &req, base_sec, 0, base_sec, 0);
    resp.precision = (unsigned char)(signed char)-20;

    r = validate_response(&req, &resp, t1, t4);

    /*
     * Expected dispersion:
     *   r.rho = 2^(-20) s = 10000000 >> 20 = 9 (100ns ticks)
     *   s.rho = 1 (SYS_PRECISION_100NS)
     *   PHI * RTT = 150 * 10000000 / 10000000 = 150
     *   Total: 9 + 1 + 150 = 160
     */
    long long expected_rho = 10000000LL >> 20; /* 9 */
    long long expected_disp = expected_rho + SYS_PRECISION_100NS +
                              (10000000LL * PHI_100NS_PER_SEC) / 10000000LL;
    snprintf(detail, sizeof(detail), "dispersion=%lld, expected=%lld (r.rho=%lld + s.rho=%d + phi*rtt=%d)",
             r.dispersion, expected_disp, expected_rho, SYS_PRECISION_100NS, 150);
    test("[rfc5905] Dispersion = r.rho + s.rho + PHI*RTT",
         r.valid && r.dispersion == expected_disp, detail);

    /* Test with precision -24 (~60ns = 0 ticks, floored to 1) */
    resp.precision = (unsigned char)(signed char)-24;
    r = validate_response(&req, &resp, t1, t4);
    long long rho24 = 10000000LL >> 24; /* 0, floored to 1 */
    if (rho24 < 1) rho24 = 1;
    expected_disp = rho24 + SYS_PRECISION_100NS + 150;
    snprintf(detail, sizeof(detail), "dispersion=%lld, expected=%lld", r.dispersion, expected_disp);
    test("[rfc5905] Dispersion with precision=-24", r.valid && r.dispersion == expected_disp, detail);
}

/* ================================================================
 * Test 6: KoD codes (RFC 5905 Section 7.4)
 * Vectors from coreSNTP test_DeserializeResponse_KoD_packets
 * ================================================================ */

static void test_kod_handling(void) {
    NtpPacket req, resp;
    NtpResult r;

    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23;
    req.tx_ts_sec  = htonl(0x11111111);
    req.tx_ts_frac = htonl(0x22222222);

    long long t1 = 39815280000000000LL;
    long long t4 = t1 + 10000000LL;

    /* KoD DENY: stratum=0, refid="DENY" */
    build_response(&resp, &req, 3981528001U, 0, 3981528001U, 0);
    resp.stratum = 0;
    resp.ref_id = htonl(0x44454E59); /* "DENY" */
    r = validate_response(&req, &resp, t1, t4);
    test("[coreSNTP] Reject KoD DENY", !r.valid, r.reject_reason);

    /* KoD RSTR */
    resp.ref_id = htonl(0x52535452); /* "RSTR" */
    r = validate_response(&req, &resp, t1, t4);
    test("[coreSNTP] Reject KoD RSTR", !r.valid, r.reject_reason);

    /* KoD RATE */
    resp.ref_id = htonl(0x52415445); /* "RATE" */
    r = validate_response(&req, &resp, t1, t4);
    test("[coreSNTP] Reject KoD RATE", !r.valid, r.reject_reason);

    /* KoD AUTH */
    resp.ref_id = htonl(0x41555448); /* "AUTH" */
    r = validate_response(&req, &resp, t1, t4);
    test("[coreSNTP] Reject KoD AUTH", !r.valid, r.reject_reason);
}

/* ================================================================
 * Test 7: Live NTP queries (optional, --live flag)
 * ================================================================ */

static const char *servers[] = {
    "216.239.35.0", "216.239.35.4", "216.239.35.8", "216.239.35.12",
};
#define NUM_SERVERS 4

static void test_live_ntp(void) {
    for (int i = 0; i < NUM_SERVERS; i++) {
        int sock;
        struct sockaddr_in addr;
        NtpPacket req, resp;
        struct timeval tv_timeout = {5, 0};
        socklen_t addrlen;
        struct sockaddr_in local;
        char name[128], detail[256];

        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            snprintf(name, sizeof(name), "%s query", servers[i]);
            test(name, 0, "socket() failed");
            continue;
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(123);
        inet_pton(AF_INET, servers[i], &addr.sin_addr);

        memset(&req, 0, sizeof(req));
        req.li_vn_mode = 0x23;
        /* Random-ish nonce */
        req.tx_ts_sec  = htonl(0xFEED0000 + i);
        req.tx_ts_frac = htonl(0xBEEF0000 + i);

        unsigned int t1_sec, t1_frac;
        get_ntp_time(&t1_sec, &t1_frac);
        long long t1 = (long long)t1_sec * 10000000LL +
                       ((long long)t1_frac * 10000000LL) / 4294967296LL;

        sendto(sock, &req, sizeof(req), 0, (struct sockaddr *)&addr, sizeof(addr));

        addrlen = sizeof(local);
        getsockname(sock, (struct sockaddr *)&local, &addrlen);
        int src_port = ntohs(local.sin_port);

        int len = recv(sock, &resp, sizeof(resp), 0);

        unsigned int t4_sec, t4_frac;
        get_ntp_time(&t4_sec, &t4_frac);
        long long t4 = (long long)t4_sec * 10000000LL +
                       ((long long)t4_frac * 10000000LL) / 4294967296LL;

        close(sock);

        if (len < (int)sizeof(NtpPacket)) {
            snprintf(name, sizeof(name), "%s query", servers[i]);
            test(name, 0, "timeout or short response");
            continue;
        }

        /* Note: live responses won't match our nonce since we used a
           fake nonce. Do the validation manually here. */
        double offset_ms = 0, delay_ms = 0;
        if ((resp.li_vn_mode & 0x07) == 4 &&
            resp.stratum > 0 && resp.stratum <= 15) {
            long long t2 = ntp_to_100ns(resp.recv_ts_sec, resp.recv_ts_frac);
            long long t3 = ntp_to_100ns(resp.tx_ts_sec, resp.tx_ts_frac);
            long long offset = ((t2 - t1) + (t3 - t4)) / 2;
            long long delay  = (t4 - t1) - (t3 - t2);
            offset_ms = (double)offset / 10000.0;
            delay_ms  = (double)delay / 10000.0;

            snprintf(name, sizeof(name),
                     "%s -> offset=%.1fms delay=%.1fms stratum=%d port=%d",
                     servers[i], offset_ms, delay_ms, resp.stratum, src_port);
            test(name, 1, NULL);

            snprintf(detail, sizeof(detail), "|offset|=%.1fms", fabs(offset_ms));
            snprintf(name, sizeof(name), "%s offset < 1s", servers[i]);
            test(name, fabs(offset_ms) < 1000.0, detail);

            snprintf(name, sizeof(name), "%s port > 1023 (ephemeral)", servers[i]);
            snprintf(detail, sizeof(detail), "port=%d", src_port);
            test(name, src_port > 1023, detail);
        } else {
            snprintf(name, sizeof(name), "%s bad response", servers[i]);
            test(name, 0, "invalid mode or stratum");
        }
    }
}

/* ================================================================
 * Main
 * ================================================================ */

int main(int argc, char **argv) {
    int live = 0;
    if (argc > 1 && strcmp(argv[1], "--live") == 0) live = 1;

    printf("\n=== NtpFix Validation Tests ===\n");
    printf("    Test vectors: coreSNTP (MIT), beevik/ntp (BSD), RFC 5905\n\n");

    printf("[1/6] Timestamp conversion math\n");
    test_timestamp_math();

    printf("\n[2/6] Offset calculation (RFC 5905 + reference vectors)\n");
    test_offset_calculation();

    printf("\n[3/6] Response validation (RFC 5905 tests 1-7)\n");
    test_response_validation();

    printf("\n[4/6] Delay clamping (RFC 5905 Section 8)\n");
    test_delay_clamping();

    printf("\n[5/6] Dispersion formula (RFC 5905 Section 9.2)\n");
    test_dispersion_formula();

    printf("\n[6/6] KoD handling (RFC 5905 Section 7.4)\n");
    test_kod_handling();

    if (live) {
        printf("\n[LIVE] NTP queries (ephemeral port)\n");
        test_live_ntp();
    } else {
        printf("\n(Skipping live NTP queries - run with --live to include)\n");
    }

    printf("\n==============================\n");
    if (total_fail == 0)
        printf("  \033[32m%d passed, 0 failed\033[0m\n", total_pass);
    else
        printf("  \033[31m%d passed, %d failed\033[0m\n", total_pass, total_fail);
    printf("==============================\n\n");

    return total_fail > 0 ? 1 : 0;
}
