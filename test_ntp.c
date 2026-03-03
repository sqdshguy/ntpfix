/*
 * test_ntp.c - Test the NTP client logic from ntpfix on macOS/Linux
 *
 * Verifies: ephemeral port NTP, offset calculation, timestamp math.
 * Build: cc -o test_ntp test_ntp.c
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

/* Get current time as NTP timestamp (seconds + fraction) */
static void get_ntp_time(unsigned int *sec, unsigned int *frac) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *sec  = (unsigned int)(tv.tv_sec + NTP_UNIX_OFFSET);
    *frac = (unsigned int)((double)tv.tv_usec * 4294.967296); /* usec to NTP frac */
}

/* Convert NTP timestamp to double seconds (relative to NTP epoch) */
static double ntp_to_double(unsigned int sec_net, unsigned int frac_net) {
    unsigned int sec  = ntohl(sec_net);
    unsigned int frac = ntohl(frac_net);
    return (double)sec + (double)frac / 4294967296.0;
}

/* Same conversion used in ntpfix.dll but in 100ns units */
static long long ntp_to_100ns(unsigned int sec_net, unsigned int frac_net) {
    unsigned int sec  = ntohl(sec_net);
    unsigned int frac = ntohl(frac_net);
    return (long long)sec * 10000000LL +
           ((long long)frac * 10000000LL) / 4294967296LL;
}

static const char *servers[] = {
    "216.239.35.0",
    "216.239.35.4",
    "216.239.35.8",
    "216.239.35.12",
};
#define NUM_SERVERS 4

typedef struct {
    const char *name;
    int passed;
    char detail[256];
} TestResult;

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

/* Test 1: NTP query from ephemeral port */
static int test_ephemeral_ntp(int server_idx, double *out_offset_ms,
                               double *out_delay_ms, int *out_stratum,
                               int *out_src_port) {
    int sock;
    struct sockaddr_in addr;
    NtpPacket req, resp;
    struct timeval tv_timeout;
    unsigned int t1_sec, t1_frac;
    double t1, t2, t3, t4, offset, delay;
    socklen_t addrlen;
    struct sockaddr_in local;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return 0;

    /* NO bind to port 123 — ephemeral port */
    tv_timeout.tv_sec = 5;
    tv_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(123);
    inet_pton(AF_INET, servers[server_idx], &addr.sin_addr);

    /* Build client request */
    memset(&req, 0, sizeof(req));
    req.li_vn_mode = 0x23; /* LI=0, VN=4, Mode=3 */

    /* Record T1 */
    get_ntp_time(&t1_sec, &t1_frac);
    t1 = (double)t1_sec + (double)t1_frac / 4294967296.0;

    sendto(sock, &req, sizeof(req), 0, (struct sockaddr *)&addr, sizeof(addr));

    /* Get local port */
    addrlen = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &addrlen);
    *out_src_port = ntohs(local.sin_port);

    /* Receive */
    if (recv(sock, &resp, sizeof(resp), 0) < (int)sizeof(NtpPacket)) {
        close(sock);
        return 0;
    }

    /* Record T4 */
    unsigned int t4_sec_raw, t4_frac_raw;
    get_ntp_time(&t4_sec_raw, &t4_frac_raw);
    t4 = (double)t4_sec_raw + (double)t4_frac_raw / 4294967296.0;

    close(sock);

    /* Verify response */
    if ((resp.li_vn_mode & 0x07) != 4) return 0;
    if (resp.stratum == 0 || resp.stratum > 15) return 0;

    /* Extract T2, T3 */
    t2 = ntp_to_double(resp.recv_ts_sec, resp.recv_ts_frac);
    t3 = ntp_to_double(resp.tx_ts_sec, resp.tx_ts_frac);

    /* NTP offset and delay */
    offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    delay  = (t4 - t1) - (t3 - t2);

    *out_offset_ms = offset * 1000.0;
    *out_delay_ms  = delay * 1000.0;
    *out_stratum   = resp.stratum;

    return 1;
}

/* Test 2: Verify 100ns conversion matches double conversion */
static void test_timestamp_math(void) {
    /* Known NTP timestamp: 2026-03-03 18:00:00 UTC */
    /* Seconds since 1900: 3981528000 (approximate) */
    unsigned int test_sec  = htonl(3981528000U);
    unsigned int test_frac = htonl(2147483648U); /* 0.5 seconds */

    long long hns = ntp_to_100ns(test_sec, test_frac);
    double    dbl = ntp_to_double(test_sec, test_frac);

    /* hns should be seconds * 10^7 */
    double hns_as_sec = (double)hns / 10000000.0;
    double diff = fabs(hns_as_sec - dbl);

    char detail[256];
    snprintf(detail, sizeof(detail),
             "100ns=%lld (%.6fs), double=%.6fs, diff=%.9fs",
             hns, hns_as_sec, dbl, diff);

    test("100ns conversion matches double conversion", diff < 0.000001, detail);

    /* Verify the 0.5s fraction */
    long long expected = 39815280005000000LL; /* 3981528000.5 * 10^7 */
    snprintf(detail, sizeof(detail),
             "expected=%lld, got=%lld, diff=%lld",
             expected, hns, hns - expected);
    test("Fractional timestamp (0.5s) is correct", llabs(hns - expected) < 10, detail);
}

/* Test 3: Verify offset calculation in 100ns units matches double */
static void test_offset_100ns(void) {
    /*
     * Simulate: local clock is 50ms ahead of server
     *   offset (theta) = remote - local = -50ms
     *   d1 = d2 = 15ms, server processing = 1ms
     *
     * In real time, if we send at real time t0:
     *   T1 = t0 + 50ms            (local clock, ahead by 50ms)
     *   T2 = t0 + 15ms            (server receive, in server time = real time)
     *   T3 = t0 + 16ms            (server transmit)
     *   T4 = t0 + 31ms + 50ms     (local clock when response arrives)
     *
     * Using S = T1:
     *   T1 = S
     *   T2 = S - 35ms   (t0+15 = (S-50)+15 = S-35)
     *   T3 = S - 34ms
     *   T4 = S + 31ms   (t0+81 = (S-50)+81 = S+31)
     */
    unsigned int now_sec, now_frac;
    get_ntp_time(&now_sec, &now_frac);

    long long S = (long long)now_sec * 10000000LL +
                  ((long long)now_frac * 10000000LL) / 4294967296LL;

    long long t1_100ns = S;
    long long t2_100ns = S - 350000LL;   /* S - 35ms */
    long long t3_100ns = S - 340000LL;   /* S - 34ms */
    long long t4_100ns = S + 310000LL;   /* S + 31ms */

    /* Offset = ((T2-T1) + (T3-T4)) / 2 */
    long long offset = ((t2_100ns - t1_100ns) + (t3_100ns - t4_100ns)) / 2;
    double offset_ms = (double)offset / 10000.0;

    char detail[256];
    snprintf(detail, sizeof(detail), "offset=%lld (%.3fms), expected -50ms", offset, offset_ms);

    /* Should be exactly -500000 (= -50ms) */
    test("Simulated 50ms offset calculation", offset == -500000LL, detail);

    /* Delay = (T4-T1) - (T3-T2) */
    long long delay = (t4_100ns - t1_100ns) - (t3_100ns - t2_100ns);
    double delay_ms = (double)delay / 10000.0;
    snprintf(detail, sizeof(detail), "delay=%lld (%.3fms), expected 30ms", delay, delay_ms);
    test("Simulated delay calculation", delay == 300000LL, detail);
}

int main(void) {
    printf("\n=== NtpFix Core Logic Tests (macOS) ===\n\n");

    /* Test 1: Timestamp math */
    printf("[1/4] Timestamp conversion math\n");
    test_timestamp_math();

    /* Test 2: Offset calculation with simulated values */
    printf("\n[2/4] Offset calculation (simulated)\n");
    test_offset_100ns();

    /* Test 3: Live NTP query from ephemeral port */
    printf("\n[3/4] Live NTP queries (ephemeral port)\n");
    for (int i = 0; i < NUM_SERVERS; i++) {
        double offset_ms, delay_ms;
        int stratum, src_port;
        char name[128], detail[256];

        if (test_ephemeral_ntp(i, &offset_ms, &delay_ms, &stratum, &src_port)) {
            snprintf(name, sizeof(name), "%s -> offset=%.1fms delay=%.1fms stratum=%d port=%d",
                     servers[i], offset_ms, delay_ms, stratum, src_port);
            test(name, 1, NULL);

            snprintf(detail, sizeof(detail), "|offset|=%.1fms", fabs(offset_ms));
            snprintf(name, sizeof(name), "%s offset < 1 second", servers[i]);
            test(name, fabs(offset_ms) < 1000.0, detail);
        } else {
            snprintf(name, sizeof(name), "%s query failed", servers[i]);
            test(name, 0, "timeout or invalid response");
        }
    }

    /* Test 4: Verify port 123 is blocked (same ISP test) */
    printf("\n[4/4] Port 123 blocked (ISP check)\n");
    {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in addr;
        struct timeval tv = {3, 0};
        NtpPacket req = {0};
        char resp[48];
        int blocked;

        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(123);
        addr.sin_addr.s_addr = INADDR_ANY;
        bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        req.li_vn_mode = 0x23;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(123);
        inet_pton(AF_INET, "216.239.35.8", &addr.sin_addr);

        sendto(sock, &req, sizeof(req), 0, (struct sockaddr *)&addr, sizeof(addr));
        blocked = (recv(sock, resp, sizeof(resp), 0) < 48);
        close(sock);

        test("Port 123 -> 123 is blocked by ISP", blocked,
             blocked ? "Confirmed: ISP drops NTP to low dest ports"
                     : "Unexpected: port 123 works (ISP may not be filtering)");
    }

    /* Summary */
    printf("\n==============================\n");
    if (total_fail == 0)
        printf("  \033[32m%d passed, 0 failed\033[0m\n", total_pass);
    else
        printf("  \033[31m%d passed, %d failed\033[0m\n", total_pass, total_fail);
    printf("==============================\n\n");

    return total_fail > 0 ? 1 : 0;
}
