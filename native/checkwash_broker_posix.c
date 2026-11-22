/*
 * checkwash_broker_posix.c — Linux Native Process-Tree & Subreaper Lifecycle Broker
 *
 * Implements the identical CWBROKER1 wire protocol as native/checkwash_broker.c
 * for Linux x64 (Phase 0B B05, B06, B07, B08, B09, B10):
 * 1. Marks the broker as PR_SET_CHILD_SUBREAPER before fork() so double-forked or
 *    setsid() grandchildren reparent to this broker (never escaping to PID 1).
 * 2. Places the child into a dedicated process group (setpgid(child, child)), sets
 *    PR_SET_PDEATHSIG(SIGKILL) with parent-PID race verification, and closes all
 *    stray file descriptors >= 3 before execve() so zero broker handles leak (B05).
 * 3. Holds the forked child on a pre-execve gate pipe; if containment or simulated
 *    assignment fails (B07), terminates the gated child with SIGKILL before chdir/execve
 *    and confirms 0 active processes.
 * 4. Reports pre-image chdir/execve errno synchronously via an O_CLOEXEC error pipe
 *    as status="spawn_failed".
 * 5. Monitors stdin in a dedicated watchdog thread: if "CANCEL" arrives or stdin
 *    hits EOF (Extension Host reload or SIGKILL crash, B08), immediately triggers
 *    full process-group + /proc subreaper tree SIGKILL and waitpid() reaping.
 * 6. Enforces strict stdout/stderr byte caps, strict RFC 3629 UTF-8 validation on
 *    all request strings, and wall-clock timeout; reports cleanupConfirmed=true ONLY
 *    after /proc verification confirms activeProcessesRemaining == 0.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int pipeReadFd;
    int abortWriteFd;
    uint8_t *buffer;
    size_t length;
    size_t capacity;
    size_t maxBytes;
    volatile int overflowed;
} StreamCollector;

typedef struct {
    int stdinFd;
    int abortWriteFd;
    volatile int cancelRequested;
    volatile int hostDisconnected;
} WatchdogContext;

static int g_sigchldPipeWriteFd = -1;
static WatchdogContext g_watchdog;

static void notify_fd(int fd, char tag) {
    if (fd < 0) return;
    ssize_t r;
    do {
        r = write(fd, &tag, 1);
    } while (r < 0 && errno == EINTR);
}

static void sigchld_handler(int sig) {
    (void)sig;
    int savedErrno = errno;
    if (g_sigchldPipeWriteFd >= 0) {
        char c = 'C';
        ssize_t r = write(g_sigchldPipeWriteFd, &c, 1);
        (void)r;
    }
    errno = savedErrno;
}

static void drain_nonblocking_fd(int fd) {
    char buf[256];
    while (read(fd, buf, sizeof(buf)) > 0) {
        /* drain */
    }
}

static void write_file_atomic_text(const char *path, const char *text) {
    if (!path || !path[0] || !text) return;
    size_t pathLen = strlen(path);
    size_t tmpCap = pathLen + 40;
    char *tmpPath = (char *)malloc(tmpCap);
    if (!tmpPath) return;
    snprintf(tmpPath, tmpCap, "%s.tmp.%ld", path, (long)getpid());
    int fd = open(tmpPath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
        size_t total = strlen(text);
        size_t off = 0;
        int ok = 1;
        while (off < total) {
            ssize_t w = write(fd, text + off, total - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                ok = 0;
                break;
            }
            off += (size_t)w;
        }
        close(fd);
        if (ok) {
            if (rename(tmpPath, path) != 0) {
                unlink(tmpPath);
            }
        } else {
            unlink(tmpPath);
        }
    }
    free(tmpPath);
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void sleep_ms(unsigned int ms) {
    struct timespec req;
    req.tv_sec = (time_t)(ms / 1000U);
    req.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        /* continue */
    }
}

/*
 * Strict RFC 3629 UTF-8 validation (rejects overlong forms, surrogates U+D800..U+DFFF,
 * codepoints > U+10FFFF, and embedded NUL bytes inside C strings).
 */
static int is_valid_utf8_no_nul(const uint8_t *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t b0 = s[i];
        if (b0 == 0) {
            return 0;
        }
        if (b0 < 0x80) {
            i += 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
            if (i + 1 >= len) return 0;
            uint8_t b1 = s[i + 1];
            if ((b1 & 0xC0) != 0x80) return 0;
            i += 2;
        } else if (b0 == 0xE0) {
            if (i + 2 >= len) return 0;
            uint8_t b1 = s[i + 1], b2 = s[i + 2];
            if (b1 < 0xA0 || b1 > 0xBF || (b2 & 0xC0) != 0x80) return 0;
            i += 3;
        } else if ((b0 >= 0xE1 && b0 <= 0xEC) || (b0 >= 0xEE && b0 <= 0xEF)) {
            if (i + 2 >= len) return 0;
            uint8_t b1 = s[i + 1], b2 = s[i + 2];
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) return 0;
            i += 3;
        } else if (b0 == 0xED) {
            /* Exclude UTF-16 surrogates U+D800..U+DFFF (ED A0 80 .. ED BF BF) */
            if (i + 2 >= len) return 0;
            uint8_t b1 = s[i + 1], b2 = s[i + 2];
            if (b1 < 0x80 || b1 > 0x9F || (b2 & 0xC0) != 0x80) return 0;
            i += 3;
        } else if (b0 == 0xF0) {
            if (i + 3 >= len) return 0;
            uint8_t b1 = s[i + 1], b2 = s[i + 2], b3 = s[i + 3];
            if (b1 < 0x90 || b1 > 0xBF || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) return 0;
            i += 4;
        } else if (b0 >= 0xF1 && b0 <= 0xF3) {
            if (i + 3 >= len) return 0;
            uint8_t b1 = s[i + 1], b2 = s[i + 2], b3 = s[i + 3];
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) return 0;
            i += 4;
        } else if (b0 == 0xF4) {
            if (i + 3 >= len) return 0;
            uint8_t b1 = s[i + 1], b2 = s[i + 2], b3 = s[i + 3];
            if (b1 < 0x80 || b1 > 0x8F || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) return 0;
            i += 4;
        } else {
            return 0;
        }
    }
    return 1;
}

static void *stream_reader_thread(void *param) {
    StreamCollector *sc = (StreamCollector *)param;
    uint8_t chunk[65536];

    for (;;) {
        ssize_t n = read(sc->pipeReadFd, chunk, sizeof(chunk));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) {
            break;
        }
        size_t bytesRead = (size_t)n;
        if (sc->length + bytesRead > sc->maxBytes) {
            __atomic_store_n(&sc->overflowed, 1, __ATOMIC_SEQ_CST);
            notify_fd(sc->abortWriteFd, 'O');
            break;
        }
        if (sc->length + bytesRead > sc->capacity) {
            size_t newCap = sc->capacity == 0 ? 65536 : sc->capacity * 2;
            while (newCap < sc->length + bytesRead) {
                newCap *= 2;
            }
            if (newCap > sc->maxBytes + 65536) {
                newCap = sc->maxBytes + 65536;
            }
            uint8_t *newBuf = (uint8_t *)realloc(sc->buffer, newCap);
            if (!newBuf) {
                __atomic_store_n(&sc->overflowed, 1, __ATOMIC_SEQ_CST);
                notify_fd(sc->abortWriteFd, 'O');
                break;
            }
            sc->buffer = newBuf;
            sc->capacity = newCap;
        }
        memcpy(sc->buffer + sc->length, chunk, bytesRead);
        sc->length += bytesRead;
    }
    return NULL;
}

static void *stdin_watchdog_thread(void *param) {
    WatchdogContext *ctx = (WatchdogContext *)param;
    char rolling[512];
    size_t rollingLen = 0;
    char chunk[256];

    for (;;) {
        ssize_t n = read(ctx->stdinFd, chunk, sizeof(chunk));
        if (n < 0) {
            if (errno == EINTR) continue;
            __atomic_store_n(&ctx->hostDisconnected, 1, __ATOMIC_SEQ_CST);
            notify_fd(ctx->abortWriteFd, 'D');
            return NULL;
        }
        if (n == 0) {
            __atomic_store_n(&ctx->hostDisconnected, 1, __ATOMIC_SEQ_CST);
            notify_fd(ctx->abortWriteFd, 'D');
            return NULL;
        }
        size_t copyLen = (size_t)n;
        if (rollingLen + copyLen > sizeof(rolling) - 1) {
            size_t keep = (sizeof(rolling) - 1) - copyLen;
            memmove(rolling, rolling + (rollingLen - keep), keep);
            rollingLen = keep;
        }
        memcpy(rolling + rollingLen, chunk, copyLen);
        rollingLen += copyLen;
        rolling[rollingLen] = '\0';
        if (strstr(rolling, "CANCEL") != NULL) {
            __atomic_store_n(&ctx->cancelRequested, 1, __ATOMIC_SEQ_CST);
            notify_fd(ctx->abortWriteFd, 'X');
            return NULL;
        }
    }
}

static char *base64_encode(const uint8_t *data, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outLen = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(outLen + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = tbl[(triple >> 18) & 0x3F];
        out[j++] = tbl[(triple >> 12) & 0x3F];
        out[j++] = tbl[(triple >> 6) & 0x3F];
        out[j++] = tbl[triple & 0x3F];
    }
    size_t mod = len % 3;
    if (mod == 1) {
        out[outLen - 1] = '=';
        out[outLen - 2] = '=';
    } else if (mod == 2) {
        out[outLen - 1] = '=';
    }
    out[outLen] = '\0';
    return out;
}

static uint8_t *base64_decode(const char *in, size_t *outLen) {
    size_t len = strlen(in);
    if (len == 0) {
        *outLen = 0;
        uint8_t *empty = (uint8_t *)malloc(1);
        if (empty) empty[0] = 0;
        return empty;
    }
    uint8_t dtable[256];
    memset(dtable, 0x80, 256);
    for (int i = 'A'; i <= 'Z'; i++) dtable[i] = (uint8_t)(i - 'A');
    for (int i = 'a'; i <= 'z'; i++) dtable[i] = (uint8_t)(26 + i - 'a');
    for (int i = '0'; i <= '9'; i++) dtable[i] = (uint8_t)(52 + i - '0');
    dtable[(unsigned char)'+'] = 62;
    dtable[(unsigned char)'/'] = 63;
    dtable[(unsigned char)'='] = 0;

    size_t allocLen = (len / 4) * 3 + 4;
    uint8_t *out = (uint8_t *)malloc(allocLen);
    if (!out) return NULL;

    size_t j = 0;
    uint32_t buf = 0;
    int bits = 0;
    int pad = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') {
            pad++;
            buf <<= 6;
            bits += 6;
        } else {
            uint8_t v = dtable[c];
            if (v & 0x80) continue;
            buf = (buf << 6) | v;
            bits += 6;
        }
        if (bits == 24) {
            out[j++] = (uint8_t)((buf >> 16) & 0xFF);
            if (pad < 2) out[j++] = (uint8_t)((buf >> 8) & 0xFF);
            if (pad < 1) out[j++] = (uint8_t)(buf & 0xFF);
            buf = 0;
            bits = 0;
            if (pad > 0) break;
        }
    }
    out[j] = 0;
    *outLen = j;
    return out;
}

static char *read_first_line_fd(int fd) {
    size_t cap = 65536;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    char ch = 0;
    ssize_t n = 0;
    for (;;) {
        n = read(fd, &ch, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) {
            break;
        }
        if (ch == '\n') break;
        if (ch == '\r') continue;
        if (len + 2 >= cap) {
            cap *= 2;
            if (cap > 32 * 1024 * 1024) {
                free(buf);
                return NULL;
            }
            char *nb = (char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
        }
        buf[len++] = ch;
    }
    if (len == 0 && n <= 0) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

typedef struct {
    pid_t pid;
    pid_t ppid;
    pid_t pgrp;
    char state;
} ProcEntry;

static int read_proc_stat_entry(pid_t pid, ProcEntry *out) {
    char pathBuf[64];
    snprintf(pathBuf, sizeof(pathBuf), "/proc/%d/stat", (int)pid);
    int fd = open(pathBuf, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char statBuf[2048];
    ssize_t n = read(fd, statBuf, sizeof(statBuf) - 1);
    close(fd);
    if (n <= 0) return 0;
    statBuf[n] = '\0';

    char *rparen = strrchr(statBuf, ')');
    if (!rparen || rparen[1] != ' ') return 0;

    char stateCh = 0;
    int ppidInt = 0, pgrpInt = 0;
    if (sscanf(rparen + 2, "%c %d %d", &stateCh, &ppidInt, &pgrpInt) != 3) {
        return 0;
    }
    out->pid = pid;
    out->ppid = (pid_t)ppidInt;
    out->pgrp = (pid_t)pgrpInt;
    out->state = stateCh;
    return 1;
}

static int has_ancestor_in_table(
    const ProcEntry *entries,
    size_t count,
    pid_t startPpid,
    pid_t brokerPid,
    pid_t childPid
) {
    pid_t cur = startPpid;
    for (size_t depth = 0; depth < 128 && cur > 1; depth++) {
        if (cur == brokerPid || (childPid > 0 && cur == childPid)) {
            return 1;
        }
        pid_t nextPpid = 0;
        for (size_t i = 0; i < count; i++) {
            if (entries[i].pid == cur) {
                nextPpid = entries[i].ppid;
                break;
            }
        }
        if (nextPpid <= 0 || nextPpid == cur) {
            break;
        }
        cur = nextPpid;
    }
    return 0;
}

static void reap_zombies_nonblocking(pid_t childPid, int *childReaped, int *childWstatus) {
    int ws = 0;
    pid_t w;
    while ((w = waitpid(-1, &ws, WNOHANG)) > 0) {
        if (w == childPid && childReaped && !(*childReaped)) {
            *childReaped = 1;
            if (childWstatus) {
                *childWstatus = ws;
            }
        }
    }
}

/*
 * Scans /proc to find all processes belonging to this broker's managed subtree
 * (either in process group `childPid` or having `brokerPid` / `childPid` in their ppid chain).
 * If sendKill != 0, sends SIGKILL to each matching process and its process group (if distinct from broker's).
 * Returns the count of matching processes still present in /proc. Sets *queryOkOut = 1 if /proc was readable.
 */
static size_t scan_and_kill_managed_processes(
    pid_t brokerPid,
    pid_t brokerPgrp,
    pid_t childPid,
    int sendKill,
    int *queryOkOut
) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        *queryOkOut = 0;
        return 999999;
    }

    size_t cap = 256;
    size_t count = 0;
    ProcEntry *entries = (ProcEntry *)malloc(cap * sizeof(ProcEntry));
    if (!entries) {
        closedir(dir);
        *queryOkOut = 0;
        return 999999;
    }

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        const char *name = de->d_name;
        if (name[0] < '1' || name[0] > '9') continue;
        int allDigits = 1;
        for (const char *q = name; *q; q++) {
            if (*q < '0' || *q > '9') {
                allDigits = 0;
                break;
            }
        }
        if (!allDigits) continue;
        pid_t pid = (pid_t)atoi(name);
        if (pid <= 1 || pid == brokerPid) continue;

        ProcEntry pe;
        if (!read_proc_stat_entry(pid, &pe)) continue;
        if (count >= cap) {
            cap *= 2;
            ProcEntry *nb = (ProcEntry *)realloc(entries, cap * sizeof(ProcEntry));
            if (!nb) {
                free(entries);
                closedir(dir);
                *queryOkOut = 0;
                return 999999;
            }
            entries = nb;
        }
        entries[count++] = pe;
    }
    closedir(dir);

    size_t managedCount = 0;
    for (size_t i = 0; i < count; i++) {
        const ProcEntry *pe = &entries[i];
        int belongs = 0;
        if (childPid > 0 && (pe->pid == childPid || pe->pgrp == childPid)) {
            belongs = 1;
        } else if (has_ancestor_in_table(entries, count, pe->ppid, brokerPid, childPid)) {
            belongs = 1;
        }
        if (belongs) {
            managedCount++;
            if (sendKill) {
                if (pe->pgrp > 1 && pe->pgrp != brokerPgrp) {
                    kill(-pe->pgrp, SIGKILL);
                }
                kill(pe->pid, SIGKILL);
            }
        }
    }

    free(entries);
    *queryOkOut = 1;
    return managedCount;
}

static void close_fds_from_3_except(int keepFd1, int keepFd2) {
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        int dirFd = dirfd(dir);
        int fdsToClose[1024];
        size_t nClose = 0;
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            int fd = atoi(de->d_name);
            if (fd >= 3 && fd != dirFd && fd != keepFd1 && fd != keepFd2) {
                if (nClose < sizeof(fdsToClose) / sizeof(fdsToClose[0])) {
                    fdsToClose[nClose++] = fd;
                } else {
                    close(fd);
                }
            }
        }
        closedir(dir);
        for (size_t i = 0; i < nClose; i++) {
            close(fdsToClose[i]);
        }
        return;
    }
    long maxFd = sysconf(_SC_OPEN_MAX);
    if (maxFd < 0 || maxFd > 65536) maxFd = 4096;
    for (int fd = 3; fd < (int)maxFd; fd++) {
        if (fd != keepFd1 && fd != keepFd2) {
            close(fd);
        }
    }
}

static int parse_nul_separated_strings(
    const uint8_t *raw,
    size_t rawLen,
    char ***outArray,
    size_t *outCount
) {
    size_t cap = 16;
    size_t count = 0;
    char **arr = (char **)malloc(cap * sizeof(char *));
    if (!arr) return 0;

    size_t pos = 0;
    while (pos < rawLen) {
        const uint8_t *nulPtr = (const uint8_t *)memchr(raw + pos, 0, rawLen - pos);
        size_t itemLen = nulPtr ? (size_t)(nulPtr - (raw + pos)) : (rawLen - pos);
        if (!is_valid_utf8_no_nul(raw + pos, itemLen)) {
            for (size_t i = 0; i < count; i++) free(arr[i]);
            free(arr);
            return 0;
        }
        char *copy = (char *)malloc(itemLen + 1);
        if (!copy) {
            for (size_t i = 0; i < count; i++) free(arr[i]);
            free(arr);
            return 0;
        }
        memcpy(copy, raw + pos, itemLen);
        copy[itemLen] = '\0';

        if (count + 2 >= cap) {
            cap *= 2;
            char **nb = (char **)realloc(arr, cap * sizeof(char *));
            if (!nb) {
                free(copy);
                for (size_t i = 0; i < count; i++) free(arr[i]);
                free(arr);
                return 0;
            }
            arr = nb;
        }
        arr[count++] = copy;
        pos += itemLen + 1;
    }
    arr[count] = NULL;
    *outArray = arr;
    *outCount = count;
    return 1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    if (argc >= 2 && strcmp(argv[1], "--probe") == 0) {
        if (access("/proc/self/stat", R_OK) != 0) {
            printf("{\"ok\":false,\"error\":\"/proc/self/stat is not readable\"}\n");
            return 1;
        }
        if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
            printf("{\"ok\":false,\"error\":\"prctl(PR_SET_CHILD_SUBREAPER) failed\"}\n");
            return 1;
        }
        int subreaperVal = 0;
        if (prctl(PR_GET_CHILD_SUBREAPER, &subreaperVal, 0, 0, 0) != 0 || subreaperVal != 1) {
            printf("{\"ok\":false,\"error\":\"PR_GET_CHILD_SUBREAPER verification failed\"}\n");
            return 1;
        }
        int pfd[2] = { -1, -1 };
        if (pipe2(pfd, O_CLOEXEC) != 0) {
            printf("{\"ok\":false,\"error\":\"pipe2(O_CLOEXEC) failed\"}\n");
            return 1;
        }
        int f0 = fcntl(pfd[0], F_GETFD);
        int f1 = fcntl(pfd[1], F_GETFD);
        close(pfd[0]);
        close(pfd[1]);
        if (f0 < 0 || f1 < 0 || (f0 & FD_CLOEXEC) == 0 || (f1 & FD_CLOEXEC) == 0) {
            printf("{\"ok\":false,\"error\":\"FD_CLOEXEC capability verification failed\"}\n");
            return 1;
        }
        int qOk = 0;
        size_t active = scan_and_kill_managed_processes(getpid(), getpgrp(), 0, 0, &qOk);
        if (!qOk || active != 0) {
            printf("{\"ok\":false,\"error\":\"/proc subtree accounting failed\"}\n");
            return 1;
        }
        printf("{\"ok\":true,\"protocol\":\"CWBROKER1\",\"nonInheritableJobHandle\":true,\"killOnJobClose\":true,\"breakawayAllowed\":false,\"platform\":\"linux\"}\n");
        return 0;
    }

    char *line = read_first_line_fd(STDIN_FILENO);
    if (!line) {
        printf("{\"status\":\"protocol_error\",\"error\":\"empty request line\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    char *fields[10];
    int fcount = 0;
    char *p = line;
    fields[fcount++] = p;
    while (*p && fcount < 10) {
        if (*p == '\t') {
            *p = '\0';
            fields[fcount++] = p + 1;
        }
        p++;
    }
    if (fcount != 10 || strcmp(fields[0], "CWBROKER1") != 0) {
        printf("{\"status\":\"protocol_error\",\"error\":\"invalid packet header\",\"cleanupConfirmed\":true}\n");
        free(line);
        return 2;
    }

    uint32_t timeoutMs = (uint32_t)strtoul(fields[1], NULL, 10);
    size_t maxStdoutBytes = (size_t)strtoull(fields[2], NULL, 10);
    size_t maxStderrBytes = (size_t)strtoull(fields[3], NULL, 10);
    unsigned int reqFlags = (unsigned int)strtoul(fields[4], NULL, 10);
    int simulateAssignFailure = (reqFlags & 1U) != 0;

    size_t exeLen = 0, cwdLen = 0, pidFileLen = 0, argsRawLen = 0, envRawLen = 0;
    uint8_t *exeUtf8 = base64_decode(fields[5], &exeLen);
    uint8_t *cwdUtf8 = base64_decode(fields[6], &cwdLen);
    uint8_t *pidFileUtf8 = base64_decode(fields[7], &pidFileLen);
    uint8_t *argsRaw = base64_decode(fields[8], &argsRawLen);
    uint8_t *envRaw = base64_decode(fields[9], &envRawLen);

    if (!exeUtf8 || !cwdUtf8 || !pidFileUtf8 || !argsRaw || !envRaw) {
        printf("{\"status\":\"protocol_error\",\"error\":\"base64 allocation failure\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    if (exeLen == 0 || cwdLen == 0 ||
        !is_valid_utf8_no_nul(exeUtf8, exeLen) ||
        !is_valid_utf8_no_nul(cwdUtf8, cwdLen) ||
        (pidFileLen > 0 && !is_valid_utf8_no_nul(pidFileUtf8, pidFileLen))) {
        printf("{\"status\":\"invalid_encoding\",\"error\":\"invalid UTF-8 in executable or cwd\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    char **childArgv = NULL;
    size_t childArgc = 0;
    if (!parse_nul_separated_strings(argsRaw, argsRawLen, &childArgv, &childArgc)) {
        printf("{\"status\":\"invalid_encoding\",\"error\":\"invalid UTF-8 in argv\",\"cleanupConfirmed\":true}\n");
        return 2;
    }
    if (childArgc == 0) {
        free(childArgv);
        childArgv = (char **)malloc(2 * sizeof(char *));
        childArgv[0] = strdup((const char *)exeUtf8);
        childArgv[1] = NULL;
        childArgc = 1;
    }

    char **rawEnvEntries = NULL;
    size_t rawEnvCount = 0;
    if (!parse_nul_separated_strings(envRaw, envRawLen, &rawEnvEntries, &rawEnvCount)) {
        printf("{\"status\":\"invalid_encoding\",\"error\":\"invalid UTF-8 in env\",\"cleanupConfirmed\":true}\n");
        return 2;
    }
    char **childEnvp = (char **)malloc((rawEnvCount + 1) * sizeof(char *));
    size_t childEnvCount = 0;
    for (size_t i = 0; i < rawEnvCount; i++) {
        if (rawEnvEntries[i][0] != '\0') {
            childEnvp[childEnvCount++] = rawEnvEntries[i];
        } else {
            free(rawEnvEntries[i]);
        }
    }
    childEnvp[childEnvCount] = NULL;
    free(rawEnvEntries);

    /* 1. Establish child subreaper containment BEFORE fork() */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        printf("{\"status\":\"job_error\",\"error\":\"prctl(PR_SET_CHILD_SUBREAPER) failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    int sigChldPipe[2] = { -1, -1 };
    int abortPipe[2] = { -1, -1 };
    int gatePipe[2] = { -1, -1 };
    int execErrPipe[2] = { -1, -1 };
    int outPipe[2] = { -1, -1 };
    int errPipe[2] = { -1, -1 };

    if (pipe2(sigChldPipe, O_CLOEXEC | O_NONBLOCK) != 0 ||
        pipe2(abortPipe, O_CLOEXEC | O_NONBLOCK) != 0 ||
        pipe2(gatePipe, O_CLOEXEC) != 0 ||
        pipe2(execErrPipe, O_CLOEXEC) != 0 ||
        pipe2(outPipe, O_CLOEXEC) != 0 ||
        pipe2(errPipe, O_CLOEXEC) != 0) {
        printf("{\"status\":\"pipe_error\",\"error\":\"pipe2 failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    g_sigchldPipeWriteFd = sigChldPipe[1];
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        printf("{\"status\":\"job_error\",\"error\":\"sigaction(SIGCHLD) failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    int childNullIn = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (childNullIn < 0) {
        printf("{\"status\":\"pipe_error\",\"error\":\"open(/dev/null) failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    pid_t brokerPid = getpid();
    pid_t brokerPgrp = getpgrp();

    pid_t childPid = fork();
    if (childPid < 0) {
        int forkErr = errno;
        printf("{\"status\":\"spawn_failed\",\"win32Error\":%d,\"cleanupConfirmed\":true,\"activeProcessesRemaining\":0}\n", forkErr);
        return 0;
    }

    if (childPid == 0) {
        /* Child process: establish dedicated process group & parent-death SIGKILL before gate wait */
        (void)setpgid(0, 0);
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (getppid() != brokerPid) {
            _exit(126);
        }

        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        sigaction(SIGCHLD, &dfl, NULL);
        sigaction(SIGPIPE, &dfl, NULL);
        sigset_t emptyMask;
        sigemptyset(&emptyMask);
        sigprocmask(SIG_SETMASK, &emptyMask, NULL);

        if (dup2(childNullIn, STDIN_FILENO) < 0 ||
            dup2(outPipe[1], STDOUT_FILENO) < 0 ||
            dup2(errPipe[1], STDERR_FILENO) < 0) {
            int err = errno;
            ssize_t wr = write(execErrPipe[1], &err, sizeof(err));
            (void)wr;
            _exit(127);
        }

        /* Close every fd >= 3 except gatePipe[0] and execErrPipe[1] (both O_CLOEXEC) */
        close_fds_from_3_except(gatePipe[0], execErrPipe[1]);

        char gateByte = 0;
        ssize_t gr;
        do {
            gr = read(gatePipe[0], &gateByte, 1);
        } while (gr < 0 && errno == EINTR);
        close(gatePipe[0]);
        if (gr != 1 || gateByte != 'G') {
            _exit(125);
        }

        if (chdir((const char *)cwdUtf8) != 0) {
            int err = errno;
            ssize_t wr = write(execErrPipe[1], &err, sizeof(err));
            (void)wr;
            _exit(127);
        }

        execve((const char *)exeUtf8, childArgv, childEnvp);
        int execErr = errno;
        ssize_t wr = write(execErrPipe[1], &execErr, sizeof(execErr));
        (void)wr;
        _exit(127);
    }

    /* Parent process */
    close(childNullIn);
    close(outPipe[1]);
    close(errPipe[1]);
    close(gatePipe[0]);
    close(execErrPipe[1]);

    int setpgidRes = setpgid(childPid, childPid);
    int pgrpAssigned = (setpgidRes == 0 || errno == EACCES);
    int assignErr = pgrpAssigned ? 0 : errno;

    if (simulateAssignFailure) {
        pgrpAssigned = 0;
        assignErr = EACCES;
    }

    if (!pgrpAssigned) {
        /* B07: Terminate gated child BEFORE releasing gatePipe[1] so target never executes */
        kill(childPid, SIGKILL);
        close(gatePipe[1]);
        close(execErrPipe[0]);

        int ws = 0;
        pid_t wRes;
        do {
            wRes = waitpid(childPid, &ws, 0);
        } while (wRes < 0 && errno == EINTR);
        int suspendedTerminated = (wRes == childPid);

        int qOk = 0;
        size_t activeRem = scan_and_kill_managed_processes(brokerPid, brokerPgrp, childPid, 1, &qOk);
        reap_zombies_nonblocking(childPid, NULL, NULL);
        if (qOk && activeRem > 0) {
            activeRem = scan_and_kill_managed_processes(brokerPid, brokerPgrp, childPid, 0, &qOk);
        }
        int cleanupConfirmed = suspendedTerminated && qOk && (activeRem == 0);

        close(outPipe[0]);
        close(errPipe[0]);
        printf("{\"status\":\"assign_failed\",\"win32Error\":%d,\"childPid\":%d,\"suspendedChildTerminated\":%s,\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%zu}\n",
               assignErr,
               (int)childPid,
               suspendedTerminated ? "true" : "false",
               cleanupConfirmed ? "true" : "false",
               activeRem);
        return 0;
    }

    /* Start stream collector threads and stdin watchdog thread BEFORE releasing child gate */
    StreamCollector outCollector = { outPipe[0], abortPipe[1], NULL, 0, 0, maxStdoutBytes, 0 };
    StreamCollector errCollector = { errPipe[0], abortPipe[1], NULL, 0, 0, maxStderrBytes, 0 };
    g_watchdog.stdinFd = STDIN_FILENO;
    g_watchdog.abortWriteFd = abortPipe[1];
    g_watchdog.cancelRequested = 0;
    g_watchdog.hostDisconnected = 0;

    pthread_t outThread, errThread, watchThread;
    if (pthread_create(&outThread, NULL, stream_reader_thread, &outCollector) != 0 ||
        pthread_create(&errThread, NULL, stream_reader_thread, &errCollector) != 0 ||
        pthread_create(&watchThread, NULL, stdin_watchdog_thread, &g_watchdog) != 0) {
        kill(childPid, SIGKILL);
        close(gatePipe[1]);
        close(execErrPipe[0]);
        int ws = 0;
        while (waitpid(childPid, &ws, 0) < 0 && errno == EINTR) {}
        int qOk = 0;
        size_t activeRem = scan_and_kill_managed_processes(brokerPid, brokerPgrp, childPid, 1, &qOk);
        printf("{\"status\":\"resume_failed\",\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%zu}\n",
               (qOk && activeRem == 0) ? "true" : "false", activeRem);
        return 0;
    }
    pthread_detach(watchThread);

    /* Publish pidFile atomically BEFORE releasing pre-execve gate (matching Windows CREATE_SUSPENDED ordering) */
    if (pidFileLen > 0) {
        char pidBuf[64];
        snprintf(pidBuf, sizeof(pidBuf), "%d", (int)childPid);
        write_file_atomic_text((const char *)pidFileUtf8, pidBuf);
    }

    /* Release pre-execve gate */
    char goByte = 'G';
    ssize_t gw;
    do {
        gw = write(gatePipe[1], &goByte, 1);
    } while (gw < 0 && errno == EINTR);
    close(gatePipe[1]);

    /* Check synchronous pre-image chdir/execve error via O_CLOEXEC execErrPipe */
    int childExecErrno = 0;
    ssize_t er;
    do {
        er = read(execErrPipe[0], &childExecErrno, sizeof(childExecErrno));
    } while (er < 0 && errno == EINTR);
    close(execErrPipe[0]);

    if (er == (ssize_t)sizeof(childExecErrno) && childExecErrno != 0) {
        if (pidFileLen > 0) {
            unlink((const char *)pidFileUtf8);
        }
        int ws = 0;
        while (waitpid(childPid, &ws, 0) < 0 && errno == EINTR) {}
        pthread_join(outThread, NULL);
        pthread_join(errThread, NULL);
        close(outPipe[0]);
        close(errPipe[0]);
        int qOk = 0;
        size_t activeRem = scan_and_kill_managed_processes(brokerPid, brokerPgrp, childPid, 1, &qOk);
        printf("{\"status\":\"spawn_failed\",\"win32Error\":%d,\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%zu}\n",
               childExecErrno,
               (qOk && activeRem == 0) ? "true" : "false",
               activeRem);
        return 0;
    }

    /* Wait for child exit, abort event (cancel / disconnect / stream overflow), or timeout */
    int childReaped = 0;
    int childWstatus = 0;
    int timedOut = 0;
    int aborted = 0;
    uint64_t deadlineMs = (timeoutMs == 0) ? 0 : (monotonic_ms() + (uint64_t)timeoutMs);

    for (;;) {
        reap_zombies_nonblocking(childPid, &childReaped, &childWstatus);
        if (childReaped) {
            break;
        }
        if (__atomic_load_n(&outCollector.overflowed, __ATOMIC_SEQ_CST) != 0 ||
            __atomic_load_n(&errCollector.overflowed, __ATOMIC_SEQ_CST) != 0 ||
            __atomic_load_n(&g_watchdog.cancelRequested, __ATOMIC_SEQ_CST) != 0 ||
            __atomic_load_n(&g_watchdog.hostDisconnected, __ATOMIC_SEQ_CST) != 0) {
            aborted = 1;
            break;
        }

        int waitMs = -1;
        if (timeoutMs != 0) {
            uint64_t nowMs = monotonic_ms();
            if (nowMs >= deadlineMs) {
                timedOut = 1;
                break;
            }
            uint64_t rem = deadlineMs - nowMs;
            waitMs = (rem > 60000ULL) ? 60000 : (int)rem;
        }

        struct pollfd pfds[2];
        pfds[0].fd = sigChldPipe[0];
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = abortPipe[0];
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int pr = poll(pfds, 2, waitMs);
        if (pr < 0) {
            if (errno == EINTR) continue;
            aborted = 1;
            break;
        }
        if (pr == 0 && timeoutMs != 0 && monotonic_ms() >= deadlineMs) {
            timedOut = 1;
            break;
        }
        if (pfds[0].revents & POLLIN) {
            drain_nonblocking_fd(sigChldPipe[0]);
        }
        if (pfds[1].revents & POLLIN) {
            drain_nonblocking_fd(abortPipe[0]);
            aborted = 1;
            reap_zombies_nonblocking(childPid, &childReaped, &childWstatus);
            break;
        }
    }

    /* Always terminate the entire process group AND subreaper descendant tree on exit/abort/timeout */
    kill(-childPid, SIGKILL);
    kill(childPid, SIGKILL);

    int queryOk = 0;
    size_t activeRemaining = 999;
    for (int attempt = 0; attempt < 500; attempt++) {
        reap_zombies_nonblocking(childPid, &childReaped, &childWstatus);
        size_t found = scan_and_kill_managed_processes(brokerPid, brokerPgrp, childPid, 1, &queryOk);
        reap_zombies_nonblocking(childPid, &childReaped, &childWstatus);
        if (queryOk && found == 0 && childReaped) {
            activeRemaining = 0;
            break;
        }
        if (queryOk) {
            activeRemaining = scan_and_kill_managed_processes(brokerPid, brokerPgrp, childPid, 0, &queryOk);
            reap_zombies_nonblocking(childPid, &childReaped, &childWstatus);
            if (queryOk && activeRemaining == 0 && childReaped) {
                break;
            }
        }
        sleep_ms(10);
    }

    int cleanupConfirmed = (queryOk && activeRemaining == 0 && childReaped);

    /* Wait for stdout/stderr collector threads to drain closed pipes */
    pthread_join(outThread, NULL);
    pthread_join(errThread, NULL);
    close(outPipe[0]);
    close(errPipe[0]);

    int childExitCode = 1;
    if (childReaped) {
        if (WIFEXITED(childWstatus)) {
            childExitCode = WEXITSTATUS(childWstatus);
        } else if (WIFSIGNALED(childWstatus)) {
            childExitCode = 128 + WTERMSIG(childWstatus);
        }
    }

    if (pidFileLen > 0 && cleanupConfirmed) {
        char doneBuf[64];
        snprintf(doneBuf, sizeof(doneBuf), "%d:CLEANED", (int)childPid);
        write_file_atomic_text((const char *)pidFileUtf8, doneBuf);
    }

    if (__atomic_load_n(&g_watchdog.hostDisconnected, __ATOMIC_SEQ_CST) != 0) {
        /* Host is already gone; exit cleanly after confirming process-tree teardown */
        return 0;
    }

    const char *statusStr = "completed";
    if (__atomic_load_n(&outCollector.overflowed, __ATOMIC_SEQ_CST) != 0) {
        statusStr = "stdout_overflow";
    } else if (__atomic_load_n(&errCollector.overflowed, __ATOMIC_SEQ_CST) != 0) {
        statusStr = "stderr_overflow";
    } else if (__atomic_load_n(&g_watchdog.cancelRequested, __ATOMIC_SEQ_CST) != 0) {
        statusStr = "cancelled";
    } else if (timedOut) {
        statusStr = "timed_out";
    } else if (aborted) {
        statusStr = "aborted";
    }

    char *stdoutB64 = base64_encode(outCollector.buffer ? outCollector.buffer : (const uint8_t *)"", outCollector.length);
    char *stderrB64 = base64_encode(errCollector.buffer ? errCollector.buffer : (const uint8_t *)"", errCollector.length);

    printf("{\"status\":\"%s\",\"exitCode\":%d,\"childPid\":%d,\"stdoutBytes\":%zu,\"stderrBytes\":%zu,\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%zu,\"stdoutB64\":\"%s\",\"stderrB64\":\"%s\"}\n",
           statusStr,
           childExitCode,
           (int)childPid,
           outCollector.length,
           errCollector.length,
           cleanupConfirmed ? "true" : "false",
           activeRemaining,
           stdoutB64 ? stdoutB64 : "",
           stderrB64 ? stderrB64 : "");
    fflush(stdout);

    free(stdoutB64);
    free(stderrB64);
    free(outCollector.buffer);
    free(errCollector.buffer);
    return 0;
}
