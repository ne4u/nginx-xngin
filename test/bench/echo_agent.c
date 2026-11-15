/* xnap-echo — minimal XNAP agent for benchmarking.
 *
 * Speaks just enough of SPEC.md v1 to give the engine a verdict in ~1us
 * of agent CPU: AGENT_HELLO on handshake, a fixed allow VERDICT on the
 * first NOTIFY frame of each stream (verdict-before-BODY-LAST is legal),
 * PONG on PING.  One detached thread per connection, blocking I/O.
 *
 * Cross-check on the engine-derived agent_us: each verdict carries
 * vars{agentus: <us>} = full service time of the *previous* request on
 * this conn (parse+decide+encode+write) — same distribution, logged as
 * $xngin_agentus.
 *
 *   cc -O2 -Wall -Wextra -pthread -o xnap-echo echo_agent.c
 *   ./xnap-echo -listen unix:/tmp/echo.sock   (or tcp:PORT)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define RBUF_SIZE   (128 * 1024)
#define MAX_FRAME   (1024 * 1024)    /* sanity bound, well above 16k */

#define FT_ENGINE_HELLO 0x01
#define FT_AGENT_HELLO  0x02
#define FT_DISCON       0x03
#define FT_NOTIFY       0x04
#define FT_VERDICT      0x05
#define FT_BODY         0x06
#define FT_ABORT        0x07
#define FT_PING         0x08
#define FT_PONG         0x09

#define VT_STR   0x09
#define VT_UINT  0x05               /* UINT32 encoding: tag + uvarint */
#define VT_KVL   0x0B

#define FL_FIN   0x01


static int64_t
now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t) tv.tv_sec * 1000000 + tv.tv_usec;
}


/* ---------- encoders ---------- */

static u_char *
enc_varint(u_char *p, uint64_t v)
{
    while (v >= 0x80) {
        *p++ = (u_char) (v | 0x80);
        v >>= 7;
    }
    *p++ = (u_char) v;
    return p;
}


static u_char *
enc_kv_name(u_char *p, const char *name, size_t len)
{
    p = enc_varint(p, len);
    memcpy(p, name, len);
    return p + len;
}


static u_char *
enc_kv_uint(u_char *p, const char *name, uint64_t v)
{
    p = enc_kv_name(p, name, strlen(name));
    *p++ = VT_UINT;
    return enc_varint(p, v);
}


static u_char *
enc_kv_str(u_char *p, const char *name, const void *val, size_t len)
{
    p = enc_kv_name(p, name, strlen(name));
    *p++ = VT_STR;
    p = enc_varint(p, len);
    memcpy(p, val, len);
    return p + len;
}


/* ---------- frame IO ---------- */

static size_t
varint_len(uint64_t v)
{
    size_t n = 1;
    while (v >= 0x80) {
        v >>= 7;
        n++;
    }
    return n;
}


/* emit one frame: header + payload in a single writev */
static int
send_frame(int fd, u_char type, uint32_t flags, uint64_t sid, uint64_t fid,
    const u_char *payload, size_t len)
{
    u_char        hdr[32], *p;
    size_t        flen;
    struct iovec  iov[2];

    flen = 1 + 4 + varint_len(sid) + varint_len(fid) + len;

    p = hdr;
    p = enc_varint(p, flen);
    *p++ = type;
    *p++ = (u_char) (flags >> 24);
    *p++ = (u_char) (flags >> 16);
    *p++ = (u_char) (flags >> 8);
    *p++ = (u_char) flags;
    p = enc_varint(p, sid);
    p = enc_varint(p, fid);

    iov[0].iov_base = hdr;
    iov[0].iov_len = (size_t) (p - hdr);
    iov[1].iov_base = (void *) payload;
    iov[1].iov_len = len;

    while (iov[1].iov_len || iov[0].iov_len) {
        ssize_t w = writev(fd, iov, 2);
        if (w <= 0) {
            return -1;
        }
        /* advance past the written prefix (frames are small; a second
           iteration only happens on an interrupted/partial write) */
        if ((size_t) w >= iov[0].iov_len) {
            w -= (ssize_t) iov[0].iov_len;
            iov[0].iov_len = 0;
            iov[1].iov_base = (u_char *) iov[1].iov_base + w;
            iov[1].iov_len -= (size_t) w;
        } else {
            iov[0].iov_base = (u_char *) iov[0].iov_base + w;
            iov[0].iov_len -= (size_t) w;
        }
    }
    return 0;
}


static int64_t
dec_varint(const u_char **pp, const u_char *end)
{
    const u_char *p = *pp;
    uint64_t      v = 0;
    unsigned      shift = 0;

    while (p < end) {
        u_char b = *p++;
        v |= (uint64_t) (b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *pp = p;
            return (int64_t) v;
        }
        shift += 7;
        if (shift > 63) {
            return -1;
        }
    }
    return -1;
}


static u_char  hello_payload[256];
static size_t  hello_len;

static void
build_hello(void)
{
    u_char *p = hello_payload;

    p = enc_kv_uint(p, "version", 1);
    p = enc_kv_uint(p, "max-frame-size", 16384);
    p = enc_kv_uint(p, "max-streams", 256);
    p = enc_kv_uint(p, "capabilities", 0x0f);
    p = enc_kv_str(p, "agent-id", "xnap-cecho/1", 12);
    hello_len = (size_t) (p - hello_payload);
}


/* VERDICT {action: allow, vars: {agentus: <prev svc us>}} */
static int
send_verdict(int fd, uint64_t sid, int64_t svc_us)
{
    u_char   payload[256], inner[64], num[24], *p, *q;
    size_t   nlen;

    nlen = (size_t) snprintf((char *) num, sizeof(num), "%lld",
                             (long long) svc_us);

    q = enc_kv_str(inner, "agentus", num, nlen);

    p = enc_kv_str(payload, "action", "allow", 5);
    p = enc_kv_name(p, "vars", 4);
    *p++ = VT_KVL;
    p = enc_varint(p, (uint64_t) (q - inner));
    memcpy(p, inner, (size_t) (q - inner));
    p += q - inner;

    return send_frame(fd, FT_VERDICT, FL_FIN, sid, 0,
                      payload, (size_t) (p - payload));
}


static int
handle_frame(int fd, u_char type, uint32_t flags, uint64_t sid, uint64_t fid,
    const u_char *payload, size_t len, int64_t *prev_svc)
{
    (void) flags;

    switch (type) {
    case FT_ENGINE_HELLO:
        return send_frame(fd, FT_AGENT_HELLO, 0, 0, 0,
                          hello_payload, hello_len);
    case FT_NOTIFY:
        return send_verdict(fd, sid, *prev_svc);
    case FT_PING:
        return send_frame(fd, FT_PONG, 0, sid, fid, payload, len);
    case FT_DISCON:
    case FT_ABORT:
    case FT_BODY:
    default:
        return 0;
    }
}


static void *
conn_main(void *arg)
{
    int      fd = (int) (intptr_t) arg;
    u_char  *buf;
    size_t   rpos = 0, rlast = 0;
    ssize_t  n;
    int64_t  prev_svc = 0, t0;

    buf = malloc(RBUF_SIZE);
    if (buf == NULL) {
        close(fd);
        return NULL;
    }

    for (;;) {
        n = read(fd, buf + rlast, RBUF_SIZE - rlast);
        if (n <= 0) {
            break;              /* closed / error */
        }
        rlast += (size_t) n;
        t0 = now_us();

        while (rpos < rlast) {
            const u_char *p = buf + rpos, *end = buf + rlast;
            const u_char *frame, *hp;
            int64_t       flen, sid, fid;
            u_char        type;
            uint32_t      flags;

            flen = dec_varint(&p, end);
            if (flen < 0) {
                break;          /* need more bytes */
            }
            if (flen < 6 || flen > MAX_FRAME) {
                goto done;      /* protocol error */
            }
            frame = p;
            if ((size_t) (end - frame) < (size_t) flen) {
                break;          /* need more bytes */
            }

            hp = frame;
            type = *hp++;
            flags = ((uint32_t) hp[0] << 24) | ((uint32_t) hp[1] << 16)
                    | ((uint32_t) hp[2] << 8) | hp[3];
            hp += 4;
            sid = dec_varint(&hp, frame + flen);
            fid = dec_varint(&hp, frame + flen);
            if (sid < 0 || fid < 0) {
                goto done;
            }

            if (handle_frame(fd, type, flags, (uint64_t) sid,
                             (uint64_t) fid, hp,
                             (size_t) (frame + flen - hp),
                             &prev_svc) < 0)
            {
                goto done;
            }

            rpos = (size_t) (frame + flen - buf);
        }

        /* report the whole service burst (all frames in this read) as
           the next verdict's agentus */
        prev_svc = now_us() - t0;

        if (rpos > 0) {
            memmove(buf, buf + rpos, rlast - rpos);
            rlast -= rpos;
            rpos = 0;
        }
        if (rlast == RBUF_SIZE) {
            goto done;          /* frame larger than buffer: bail */
        }
    }

done:
    free(buf);
    close(fd);
    return NULL;
}


int
main(int argc, char **argv)
{
    const char *listen_addr = "unix:/tmp/xnap-echo.sock";
    int         lfd, i;

    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-listen") == 0) {
            listen_addr = argv[++i];
        }
    }

    build_hello();
    signal(SIGPIPE, SIG_IGN);

    if (strncmp(listen_addr, "unix:", 5) == 0) {
        struct sockaddr_un un;
        const char      *path = listen_addr + 5;

        if (strlen(path) >= sizeof(un.sun_path)) {
            fprintf(stderr, "xnap-echo: unix path too long\n");
            return 1;
        }
        lfd = socket(AF_UNIX, SOCK_STREAM, 0);
        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        strcpy(un.sun_path, path);
        unlink(path);
        if (bind(lfd, (struct sockaddr *) &un, sizeof(un)) < 0) {
            perror("bind");
            return 1;
        }
        chmod(path, 0777);
    } else if (strncmp(listen_addr, "tcp:", 4) == 0) {
        struct sockaddr_in in;
        const char      *spec = listen_addr + 4, *colon;
        char             host[64];
        int              one = 1, port;

        colon = strrchr(spec, ':');
        if (colon) {
            size_t hl = (size_t) (colon - spec);
            if (hl >= sizeof(host)) {
                hl = sizeof(host) - 1;
            }
            memcpy(host, spec, hl);
            host[hl] = '\0';
            port = atoi(colon + 1);
        } else {
            strcpy(host, "127.0.0.1");
            port = atoi(spec);
        }

        lfd = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        in.sin_port = htons((uint16_t) port);
        if (inet_pton(AF_INET, host, &in.sin_addr) != 1
            || bind(lfd, (struct sockaddr *) &in, sizeof(in)) < 0)
        {
            perror("bind");
            return 1;
        }
    } else {
        fprintf(stderr, "xnap-echo: bad -listen %s\n", listen_addr);
        return 1;
    }

    if (listen(lfd, 128) < 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "xnap-echo listening on %s\n", listen_addr);

    for (;;) {
        int        cfd = accept(lfd, NULL, NULL);
        pthread_t  th;
        int        one = 1;

        if (cfd < 0) {
            continue;
        }
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        pthread_create(&th, NULL, conn_main, (void *) (intptr_t) cfd);
        pthread_detach(th);
    }
}
