#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>

static int open_sock(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); exit(1); }
    return s;
}

static void set_mode(const char *iface, const char *modestr) {
    int mode;
    if (strcmp(modestr, "monitor") == 0) mode = IW_MODE_MONITOR;
    else if (strcmp(modestr, "master") == 0) mode = IW_MODE_MASTER;
    else if (strcmp(modestr, "managed") == 0) mode = IW_MODE_INFRA;
    else if (strcmp(modestr, "adhoc") == 0) mode = IW_MODE_ADHOC;
    else if (strcmp(modestr, "auto") == 0) mode = IW_MODE_AUTO;
    else { fprintf(stderr, "modo desconocido: %s\n", modestr); exit(1); }

    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);
    wrq.u.mode = mode;

    int s = open_sock();
    if (ioctl(s, SIOCSIWMODE, &wrq) < 0) {
        fprintf(stderr, "SIOCSIWMODE fallo en %s: %s\n", iface, strerror(errno));
        exit(1);
    }
    printf("OK: modo de %s -> %s\n", iface, modestr);
}

static void get_mode(const char *iface) {
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);
    int s = open_sock();
    if (ioctl(s, SIOCGIWMODE, &wrq) < 0) {
        fprintf(stderr, "SIOCGIWMODE fallo en %s: %s\n", iface, strerror(errno));
        exit(1);
    }
    static const char *names[] = {"auto","adhoc","managed","master","repeat","second","monitor","mesh"};
    int m = wrq.u.mode;
    printf("%s modo actual: %s (%d)\n", iface, (m >= 0 && m < 8) ? names[m] : "?", m);
}

static void set_channel(const char *iface, int chan) {
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);
    wrq.u.freq.m = chan;
    wrq.u.freq.e = 0;

    int s = open_sock();
    if (ioctl(s, SIOCSIWFREQ, &wrq) < 0) {
        fprintf(stderr, "SIOCSIWFREQ fallo en %s: %s\n", iface, strerror(errno));
        exit(1);
    }
    printf("OK: canal de %s -> %d\n", iface, chan);
}

static void do_scan(const char *iface) {
    int s = open_sock();
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(s, SIOCSIWSCAN, &wrq) < 0) {
        fprintf(stderr, "SIOCSIWSCAN fallo en %s: %s "
                "(el driver puede no soportar scan estandar de kernel)\n",
                iface, strerror(errno));
        exit(1);
    }

    static unsigned char buffer[32768];
    int len = -1;
    for (int tries = 0; tries < 20; tries++) {
        usleep(500000);
        memset(&wrq, 0, sizeof(wrq));
        strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);
        wrq.u.data.pointer = buffer;
        wrq.u.data.length = sizeof(buffer);
        wrq.u.data.flags = 0;
        if (ioctl(s, SIOCGIWSCAN, &wrq) == 0) {
            len = wrq.u.data.length;
            break;
        }
        if (errno != EAGAIN) {
            fprintf(stderr, "SIOCGIWSCAN fallo: %s\n", strerror(errno));
            exit(1);
        }
    }
    if (len < 0) { fprintf(stderr, "timeout esperando resultados de scan\n"); exit(1); }

    unsigned char *pos = buffer;
    unsigned char *end = buffer + len;
    int count = 0;

    while (pos + IW_EV_LCP_LEN <= end) {
        unsigned short evlen;
        memcpy(&evlen, pos, sizeof(unsigned short));
        if (evlen < IW_EV_LCP_LEN || pos + evlen > end) break;

        struct iw_event iwe;
        memset(&iwe, 0, sizeof(iwe));
        size_t copylen = evlen < sizeof(iwe) ? evlen : sizeof(iwe);
        memcpy(&iwe, pos, copylen);

        switch (iwe.cmd) {
            case SIOCGIWAP: {
                unsigned char *ap = (unsigned char *)iwe.u.ap_addr.sa_data;
                count++;
                printf("\n[%d] BSSID: %02x:%02x:%02x:%02x:%02x:%02x",
                       count, ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
                break;
            }
            case SIOCGIWFREQ: {
                double freq = (double)iwe.u.freq.m;
                for (int i = 0; i < iwe.u.freq.e; i++) freq *= 10;
                printf("  chan/freq:%.0f", freq);
                break;
            }
            case SIOCGIWESSID: {
                unsigned short essid_len;
                memcpy(&essid_len, pos + IW_EV_LCP_LEN, sizeof(unsigned short));
                if (essid_len > 0 && essid_len < 64 && pos + IW_EV_POINT_LEN + essid_len <= end) {
                    char essid[64];
                    int n = essid_len < (int)sizeof(essid) - 1 ? essid_len : (int)sizeof(essid) - 1;
                    memcpy(essid, pos + IW_EV_POINT_LEN, n);
                    essid[n] = '\0';
                    printf("  ESSID:\"%s\"", essid);
                }
                break;
            }
            case IWEVQUAL:
                printf("  qual:%d level:%d", iwe.u.qual.qual, iwe.u.qual.level);
                break;
            default:
                break;
        }
        pos += evlen;
    }
    printf("\n--- %d redes encontradas ---\n", count);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "uso:\n"
            "  %s <iface> mode monitor|master|managed|adhoc|auto\n"
            "  %s <iface> channel <N>\n"
            "  %s <iface> getmode\n"
            "  %s <iface> scan\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    const char *cmd = argv[2];

    if (strcmp(cmd, "mode") == 0 && argc >= 4) set_mode(iface, argv[3]);
    else if (strcmp(cmd, "channel") == 0 && argc >= 4) set_channel(iface, atoi(argv[3]));
    else if (strcmp(cmd, "getmode") == 0) get_mode(iface);
    else if (strcmp(cmd, "scan") == 0) do_scan(iface);
    else { fprintf(stderr, "comando desconocido o faltan argumentos\n"); return 1; }

    return 0;
}
