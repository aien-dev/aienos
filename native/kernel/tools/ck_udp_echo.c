/* ck_udp_echo.c -- host-side UDP echo helper for scripts/qemu_ck_net_test.sh
 * (gate AIENOS_CK_NET). Hosted C (POSIX sockets), test tooling only, never
 * in the kernel image. No Python, no nc/socat.
 *
 *   ck_udp_echo PORT TOKEN LOGFILE SECONDS
 *
 * Binds 127.0.0.1:PORT (QEMU user networking forwards guest datagrams for
 * 10.0.2.2:PORT there), writes "ready port=PORT" to LOGFILE, then for SECONDS
 * answers every datagram that starts with "AIENOS-CK-NET ping " with
 *   "AIENOS-CK-NET pong token=TOKEN echo=<the datagram>"
 * and logs each one ("rx ..." / "tx ..."). TOKEN (hex, 8..64 chars) is chosen
 * by the script per run, so a guest line carrying it proves the reply came
 * from this process. Exit 0 at the deadline, 2 usage, 3 socket/bind error. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PING "AIENOS-CK-NET ping "
#define MAX_ECHO 400

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void show(FILE *lg, const unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) fputc((b[i] >= 0x20 && b[i] < 0x7f && b[i] != '"') ? b[i] : '.', lg);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: ck_udp_echo PORT TOKEN LOGFILE SECONDS\n");
        return 2;
    }
    char *end = 0;
    long port = strtol(argv[1], &end, 10);
    long secs = strtol(argv[4], 0, 10);
    const char *token = argv[2];
    size_t tl = strlen(token);
    if (*end || port < 1024 || port > 65535 || secs < 1 || secs > 3600 || tl < 8 || tl > 64 ||
        strspn(token, "0123456789abcdef") != tl) {
        fprintf(stderr, "ck_udp_echo: bad arguments\n");
        return 2;
    }
    FILE *lg = fopen(argv[3], "w");
    if (!lg) {
        perror("ck_udp_echo: log");
        return 2;
    }
    setvbuf(lg, 0, _IOLBF, 0);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(lg, "bind failed port=%ld errno=%d (%s)\n", port, errno, strerror(errno));
        fclose(lg);
        return 3;
    }
    fprintf(lg, "ready port=%ld\n", port);
    double deadline = now_s() + (double)secs;
    unsigned replies = 0;
    for (;;) {
        double left = deadline - now_s();
        if (left <= 0) break;
        struct pollfd pf = {s, POLLIN, 0};
        int pr = poll(&pf, 1, (int)(left * 1000.0) + 1);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) continue;
        unsigned char in[2048], out[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(s, in, sizeof in, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) continue;
        char fa[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &from.sin_addr, fa, sizeof fa);
        fprintf(lg, "rx from %s:%u len=%zd payload=\"", fa, ntohs(from.sin_port), n);
        show(lg, in, (size_t)n);
        fprintf(lg, "\"\n");
        if ((size_t)n < sizeof PING - 1 || memcmp(in, PING, sizeof PING - 1) != 0) {
            fprintf(lg, "ignored (not a ping)\n");
            continue;
        }
        int h = snprintf((char *)out, sizeof out, "AIENOS-CK-NET pong token=%s echo=", token);
        size_t m = (size_t)n > MAX_ECHO ? MAX_ECHO : (size_t)n;
        memcpy(out + h, in, m);
        ssize_t sent = sendto(s, out, (size_t)h + m, 0, (struct sockaddr *)&from, fl);
        fprintf(lg, "tx to %s:%u len=%zd reply=%u\n", fa, ntohs(from.sin_port), sent, ++replies);
    }
    fprintf(lg, "done replies=%u\n", replies);
    fclose(lg);
    close(s);
    return 0;
}
