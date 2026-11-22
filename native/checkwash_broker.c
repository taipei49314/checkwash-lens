/*
 * checkwash_broker.c — Windows Native Job Object & Process Tree Lifecycle Broker
 *
 * Enforces Rev 3 §7.3 & Phase 0B (B05, B06, B07, B08, B09, B10):
 * 1. Creates a non-inheritable Windows Job Object (bInheritHandle = FALSE) with
 *    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and NO breakaway flags.
 * 2. Launches the target executable with CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT
 *    | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP and explicit lpApplicationName.
 * 3. Assigns the suspended child to the Job Object BEFORE ResumeThread.
 *    If AssignProcessToJobObject fails (or simulateAssignFailure is requested for B07),
 *    terminates the suspended child, waits for its termination, and confirms 0 active processes.
 * 4. Monitors stdin in a dedicated watchdog thread: if "CANCEL" is received or stdin
 *    closes (extension host reload / crash, B08), immediately triggers job termination.
 * 5. Enforces strict stdout/stderr byte caps and wall-clock timeout; on any limit breach
 *    or normal exit, terminates the Job Object and verifies ActiveProcesses == 0 via
 *    QueryInformationJobObject(JobObjectBasicAccountingInformation) before reporting cleanupConfirmed.
 */

#define _CRT_SECURE_NO_WARNINGS
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    HANDLE hPipeRead;
    HANDLE hAbortEvent;
    uint8_t *buffer;
    size_t length;
    size_t capacity;
    size_t maxBytes;
    volatile LONG overflowed;
} StreamCollector;

typedef struct {
    HANDLE hStdin;
    HANDLE hAbortEvent;
    volatile LONG cancelRequested;
    volatile LONG hostDisconnected;
    char *pidFilePath;
} WatchdogContext;

static WCHAR *utf8_to_wide_basic(const char *utf8) {
    if (!utf8) return NULL;
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (wlen <= 0) return NULL;
    WCHAR *wstr = (WCHAR *)malloc((size_t)wlen * sizeof(WCHAR));
    if (!wstr) return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, wstr, wlen) <= 0) {
        free(wstr);
        return NULL;
    }
    return wstr;
}

static void write_file_atomic_text(const char *path, const char *text) {
    if (!path || !path[0] || !text) return;
    WCHAR *wDest = utf8_to_wide_basic(path);
    if (!wDest) return;
    size_t destLen = wcslen(wDest);
    WCHAR *wTmp = (WCHAR *)malloc((destLen + 32) * sizeof(WCHAR));
    if (!wTmp) {
        free(wDest);
        return;
    }
    _snwprintf(wTmp, destLen + 31, L"%ls.tmp.%lu", wDest, (unsigned long)GetCurrentProcessId());
    wTmp[destLen + 31] = L'\0';

    HANDLE hFile = CreateFileW(
        wTmp,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD textBytes = (DWORD)strlen(text);
        DWORD written = 0;
        BOOL writeOk = (textBytes == 0) || WriteFile(hFile, text, textBytes, &written, NULL);
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        if (writeOk && written == textBytes) {
            if (!MoveFileExW(wTmp, wDest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(wTmp);
            }
        } else {
            DeleteFileW(wTmp);
        }
    }
    free(wTmp);
    free(wDest);
}

static DWORD WINAPI stream_reader_thread(LPVOID param) {
    StreamCollector *sc = (StreamCollector *)param;
    uint8_t chunk[65536];
    DWORD bytesRead = 0;

    while (ReadFile(sc->hPipeRead, chunk, sizeof(chunk), &bytesRead, NULL) && bytesRead > 0) {
        if (sc->length + bytesRead > sc->maxBytes) {
            InterlockedExchange(&sc->overflowed, 1);
            SetEvent(sc->hAbortEvent);
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
                InterlockedExchange(&sc->overflowed, 1);
                SetEvent(sc->hAbortEvent);
                break;
            }
            sc->buffer = newBuf;
            sc->capacity = newCap;
        }
        memcpy(sc->buffer + sc->length, chunk, bytesRead);
        sc->length += bytesRead;
    }
    return 0;
}

static DWORD WINAPI stdin_watchdog_thread(LPVOID param) {
    WatchdogContext *ctx = (WatchdogContext *)param;
    char buf[256];
    char rolling[512];
    size_t rollingLen = 0;
    DWORD bytesRead = 0;

    rolling[0] = '\0';
    while (ReadFile(ctx->hStdin, buf, sizeof(buf) - 1, &bytesRead, NULL)) {
        if (bytesRead == 0) {
            InterlockedExchange(&ctx->hostDisconnected, 1);
            SetEvent(ctx->hAbortEvent);
            return 0;
        }
        for (DWORD i = 0; i < bytesRead; i++) {
            char ch = (buf[i] == '\0') ? ' ' : buf[i];
            if (rollingLen >= sizeof(rolling) - 1) {
                memmove(rolling, rolling + 256, rollingLen - 256);
                rollingLen -= 256;
            }
            rolling[rollingLen++] = ch;
        }
        rolling[rollingLen] = '\0';
        if (strstr(rolling, "CANCEL") != NULL) {
            InterlockedExchange(&ctx->cancelRequested, 1);
            SetEvent(ctx->hAbortEvent);
            return 0;
        }
    }
    InterlockedExchange(&ctx->hostDisconnected, 1);
    SetEvent(ctx->hAbortEvent);
    return 0;
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

static WCHAR *utf8_to_wide(const char *utf8) {
    if (!utf8) return NULL;
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (wlen <= 0) return NULL;
    WCHAR *wstr = (WCHAR *)malloc((size_t)wlen * sizeof(WCHAR));
    if (!wstr) return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, wstr, wlen) <= 0) {
        free(wstr);
        return NULL;
    }
    return wstr;
}

/*
 * Appends a single argument using Windows CommandLineToArgvW inverse quoting rules.
 * Preserves spaces, quotes, backslashes, Unicode, and shell meta-characters verbatim.
 */
static void append_quoted_arg(WCHAR **cmdBuf, size_t *cmdLen, size_t *cmdCap, const WCHAR *arg, int isFirst) {
    size_t argLen = wcslen(arg);
    size_t needed = *cmdLen + (argLen * 2) + 16;
    if (needed > *cmdCap) {
        size_t newCap = (*cmdCap == 0) ? 1024 : (*cmdCap * 2);
        while (newCap < needed) newCap *= 2;
        WCHAR *newBuf = (WCHAR *)realloc(*cmdBuf, newCap * sizeof(WCHAR));
        if (!newBuf) exit(101);
        *cmdBuf = newBuf;
        *cmdCap = newCap;
    }

    if (!isFirst) {
        (*cmdBuf)[(*cmdLen)++] = L' ';
    }

    int needsQuotes = (argLen == 0);
    for (size_t i = 0; i < argLen; i++) {
        if (arg[i] == L' ' || arg[i] == L'\t' || arg[i] == L'\n' || arg[i] == L'\v' || arg[i] == L'"') {
            needsQuotes = 1;
            break;
        }
    }

    if (!needsQuotes) {
        memcpy(*cmdBuf + *cmdLen, arg, argLen * sizeof(WCHAR));
        *cmdLen += argLen;
        (*cmdBuf)[*cmdLen] = L'\0';
        return;
    }

    (*cmdBuf)[(*cmdLen)++] = L'"';
    for (size_t i = 0; ; ) {
        size_t numBackslashes = 0;
        while (i < argLen && arg[i] == L'\\') {
            i++;
            numBackslashes++;
        }
        if (i == argLen) {
            for (size_t k = 0; k < numBackslashes * 2; k++) {
                (*cmdBuf)[(*cmdLen)++] = L'\\';
            }
            break;
        } else if (arg[i] == L'"') {
            for (size_t k = 0; k < numBackslashes * 2 + 1; k++) {
                (*cmdBuf)[(*cmdLen)++] = L'\\';
            }
            (*cmdBuf)[(*cmdLen)++] = L'"';
            i++;
        } else {
            for (size_t k = 0; k < numBackslashes; k++) {
                (*cmdBuf)[(*cmdLen)++] = L'\\';
            }
            (*cmdBuf)[(*cmdLen)++] = arg[i++];
        }
    }
    (*cmdBuf)[(*cmdLen)++] = L'"';
    (*cmdBuf)[*cmdLen] = L'\0';
}

/*
 * Request Packet Format (tab-separated base64 fields on a single line):
 *   Field 0: Magic "CWBROKER1"
 *   Field 1: timeoutMs (uint32)
 *   Field 2: maxStdoutBytes (size_t)
 *   Field 3: maxStderrBytes (size_t)
 *   Field 4: flags (bit 0 = simulateAssignFailure)
 *   Field 5: base64(executable UTF-8)
 *   Field 6: base64(cwd UTF-8)
 *   Field 7: base64(pidTrackFilePath UTF-8, or empty)
 *   Field 8: base64(NUL-separated UTF-8 args array, including argv[0])
 *   Field 9: base64(NUL-separated UTF-8 env KEY=VALUE entries)
 */
static char *read_first_line(HANDLE hStdin) {
    size_t cap = 65536;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    char ch = 0;
    DWORD readBytes = 0;
    while (ReadFile(hStdin, &ch, 1, &readBytes, NULL) && readBytes == 1) {
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
    if (len == 0 && readBytes == 0) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

static DWORD query_active_processes(HANDLE hJob, BOOL *okOut) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
    ZeroMemory(&acct, sizeof(acct));
    DWORD retLen = 0;
    if (!QueryInformationJobObject(hJob, JobObjectBasicAccountingInformation, &acct, sizeof(acct), &retLen)) {
        *okOut = FALSE;
        return 999999;
    }
    *okOut = TRUE;
    return acct.ActiveProcesses;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--probe") == 0) {
        HANDLE hJob = CreateJobObjectW(NULL, NULL);
        if (!hJob) {
            printf("{\"ok\":false,\"error\":\"CreateJobObjectW failed\"}\n");
            return 1;
        }
        DWORD handleFlags = 0;
        BOOL flagsOk = GetHandleInformation(hJob, &handleFlags);
        BOOL nonInheritable = flagsOk && ((handleFlags & HANDLE_FLAG_INHERIT) == 0);

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;
        ZeroMemory(&extLimit, sizeof(extLimit));
        extLimit.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        BOOL limitOk = SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &extLimit, sizeof(extLimit));
        BOOL queryOk = FALSE;
        DWORD active = query_active_processes(hJob, &queryOk);
        CloseHandle(hJob);
        if (!nonInheritable || !limitOk || !queryOk || active != 0) {
            printf("{\"ok\":false,\"error\":\"JobObject capability verification failed\"}\n");
            return 1;
        }
        printf("{\"ok\":true,\"protocol\":\"CWBROKER1\",\"nonInheritableJobHandle\":true,\"killOnJobClose\":true,\"breakawayAllowed\":false}\n");
        return 0;
    }

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    char *line = read_first_line(hStdin);
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

    DWORD timeoutMs = (DWORD)strtoul(fields[1], NULL, 10);
    size_t maxStdoutBytes = (size_t)strtoull(fields[2], NULL, 10);
    size_t maxStderrBytes = (size_t)strtoull(fields[3], NULL, 10);
    unsigned int reqFlags = (unsigned int)strtoul(fields[4], NULL, 10);
    int simulateAssignFailure = (reqFlags & 1) != 0;

    size_t exeLen = 0, cwdLen = 0, pidFileLen = 0, argsRawLen = 0, envRawLen = 0;
    uint8_t *exeUtf8 = base64_decode(fields[5], &exeLen);
    uint8_t *cwdUtf8 = base64_decode(fields[6], &cwdLen);
    uint8_t *pidFileUtf8 = base64_decode(fields[7], &pidFileLen);
    uint8_t *argsRaw = base64_decode(fields[8], &argsRawLen);
    uint8_t *envRaw = base64_decode(fields[9], &envRawLen);

    WCHAR *wExe = utf8_to_wide((const char *)exeUtf8);
    WCHAR *wCwd = utf8_to_wide((const char *)cwdUtf8);
    if (!wExe || !wCwd) {
        printf("{\"status\":\"invalid_encoding\",\"error\":\"invalid UTF-8 in executable or cwd\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    /* Build command line from NUL-separated UTF-8 args */
    WCHAR *wCmdLine = NULL;
    size_t cmdLen = 0, cmdCap = 0;
    size_t pos = 0;
    int argIdx = 0;
    while (pos < argsRawLen) {
        const char *argStr = (const char *)(argsRaw + pos);
        size_t slen = strlen(argStr);
        WCHAR *wArg = utf8_to_wide(argStr);
        if (!wArg) {
            printf("{\"status\":\"invalid_encoding\",\"error\":\"invalid UTF-8 in argv\",\"cleanupConfirmed\":true}\n");
            return 2;
        }
        append_quoted_arg(&wCmdLine, &cmdLen, &cmdCap, wArg, argIdx == 0);
        free(wArg);
        pos += slen + 1;
        argIdx++;
    }
    if (!wCmdLine) {
        append_quoted_arg(&wCmdLine, &cmdLen, &cmdCap, wExe, 1);
    }

    /* Build UTF-16 environment block (double-NUL terminated) */
    size_t envWCap = 4096;
    size_t envWLen = 0;
    WCHAR *wEnvBlock = (WCHAR *)malloc(envWCap * sizeof(WCHAR));
    pos = 0;
    while (pos < envRawLen) {
        const char *entryStr = (const char *)(envRaw + pos);
        size_t slen = strlen(entryStr);
        if (slen > 0) {
            WCHAR *wEntry = utf8_to_wide(entryStr);
            if (!wEntry) {
                printf("{\"status\":\"invalid_encoding\",\"error\":\"invalid UTF-8 in env\",\"cleanupConfirmed\":true}\n");
                return 2;
            }
            size_t wEntryLen = wcslen(wEntry);
            if (envWLen + wEntryLen + 4 >= envWCap) {
                while (envWLen + wEntryLen + 4 >= envWCap) envWCap *= 2;
                WCHAR *newEnvBlock = (WCHAR *)realloc(wEnvBlock, envWCap * sizeof(WCHAR));
                if (!newEnvBlock) {
                    free(wEntry);
                    free(wEnvBlock);
                    printf("{\"status\":\"oom\",\"error\":\"failed to allocate environment block\",\"cleanupConfirmed\":true}\n");
                    return 2;
                }
                wEnvBlock = newEnvBlock;
            }
            memcpy(wEnvBlock + envWLen, wEntry, (wEntryLen + 1) * sizeof(WCHAR));
            envWLen += wEntryLen + 1;
            free(wEntry);
        }
        pos += slen + 1;
    }
    wEnvBlock[envWLen++] = L'\0';
    wEnvBlock[envWLen] = L'\0';

    /* 1. Create non-inheritable Job Object */
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) {
        printf("{\"status\":\"job_error\",\"error\":\"CreateJobObjectW failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }
    DWORD jobHandleFlags = 0;
    if (!GetHandleInformation(hJob, &jobHandleFlags) || (jobHandleFlags & HANDLE_FLAG_INHERIT) != 0) {
        CloseHandle(hJob);
        printf("{\"status\":\"job_error\",\"error\":\"Job handle is inheritable\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;
    ZeroMemory(&extLimit, sizeof(extLimit));
    extLimit.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &extLimit, sizeof(extLimit))) {
        CloseHandle(hJob);
        printf("{\"status\":\"job_error\",\"error\":\"SetInformationJobObject failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }

    /* 2. Create stdout/stderr pipes and NUL stdin for child */
    SECURITY_ATTRIBUTES saInheritable;
    ZeroMemory(&saInheritable, sizeof(saInheritable));
    saInheritable.nLength = sizeof(saInheritable);
    saInheritable.bInheritHandle = TRUE;

    HANDLE hOutRead = NULL, hOutWrite = NULL;
    HANDLE hErrRead = NULL, hErrWrite = NULL;
    if (!CreatePipe(&hOutRead, &hOutWrite, &saInheritable, 65536) ||
        !CreatePipe(&hErrRead, &hErrWrite, &saInheritable, 65536)) {
        CloseHandle(hJob);
        printf("{\"status\":\"pipe_error\",\"error\":\"CreatePipe failed\",\"cleanupConfirmed\":true}\n");
        return 2;
    }
    /* Ensure read ends are NOT inheritable */
    SetHandleInformation(hOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrRead, HANDLE_FLAG_INHERIT, 0);

    HANDLE hChildNullIn = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      &saInheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hChildNullIn;
    si.hStdOutput = hOutWrite;
    si.hStdError = hErrWrite;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    /* 3. Launch child in CREATE_SUSPENDED state */
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    BOOL created = CreateProcessW(
        wExe,
        wCmdLine,
        NULL,
        NULL,
        TRUE,
        creationFlags,
        wEnvBlock,
        wCwd,
        &si,
        &pi
    );

    CloseHandle(hOutWrite);
    CloseHandle(hErrWrite);
    if (hChildNullIn != INVALID_HANDLE_VALUE && hChildNullIn != NULL) {
        CloseHandle(hChildNullIn);
    }

    if (!created) {
        DWORD err = GetLastError();
        CloseHandle(hOutRead);
        CloseHandle(hErrRead);
        CloseHandle(hJob);
        printf("{\"status\":\"spawn_failed\",\"win32Error\":%lu,\"cleanupConfirmed\":true,\"activeProcessesRemaining\":0}\n", (unsigned long)err);
        return 0;
    }

    if (pidFileLen > 0) {
        char pidBuf[64];
        snprintf(pidBuf, sizeof(pidBuf), "%lu", (unsigned long)pi.dwProcessId);
        write_file_atomic_text((const char *)pidFileUtf8, pidBuf);
    }

    /* 4. Assign suspended child to Job Object before ResumeThread (B07) */
    BOOL assigned = FALSE;
    DWORD assignErr = 0;
    if (simulateAssignFailure) {
        assigned = FALSE;
        assignErr = ERROR_ACCESS_DENIED;
    } else {
        assigned = AssignProcessToJobObject(hJob, pi.hProcess);
        if (!assigned) {
            assignErr = GetLastError();
        }
    }

    if (!assigned) {
        TerminateProcess(pi.hProcess, 1);
        DWORD waitRes = WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 999;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        BOOL suspendedTerminated = (waitRes == WAIT_OBJECT_0 && exitCode != STILL_ACTIVE);
        BOOL qOk = FALSE;
        DWORD activeRem = query_active_processes(hJob, &qOk);
        BOOL cleanupConfirmed = suspendedTerminated && qOk && (activeRem == 0);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hOutRead);
        CloseHandle(hErrRead);
        CloseHandle(hJob);

        printf("{\"status\":\"assign_failed\",\"win32Error\":%lu,\"childPid\":%lu,\"suspendedChildTerminated\":%s,\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%lu}\n",
               (unsigned long)assignErr,
               (unsigned long)pi.dwProcessId,
               suspendedTerminated ? "true" : "false",
               cleanupConfirmed ? "true" : "false",
               (unsigned long)activeRem);
        return 0;
    }

    HANDLE hAbortEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    StreamCollector outCollector = { hOutRead, hAbortEvent, NULL, 0, 0, maxStdoutBytes, 0 };
    StreamCollector errCollector = { hErrRead, hAbortEvent, NULL, 0, 0, maxStderrBytes, 0 };
    WatchdogContext watchdog = { hStdin, hAbortEvent, 0, 0, (char *)pidFileUtf8 };

    HANDLE hOutThread = CreateThread(NULL, 0, stream_reader_thread, &outCollector, 0, NULL);
    HANDLE hErrThread = CreateThread(NULL, 0, stream_reader_thread, &errCollector, 0, NULL);
    HANDLE hWatchThread = CreateThread(NULL, 0, stdin_watchdog_thread, &watchdog, 0, NULL);
    if (hWatchThread) {
        CloseHandle(hWatchThread);
    }

    /* 5. Resume child thread only after Job assignment and stream readers are ready */
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        TerminateJobObject(hJob, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        BOOL qOk = FALSE;
        DWORD activeRem = query_active_processes(hJob, &qOk);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hOutRead);
        CloseHandle(hErrRead);
        CloseHandle(hJob);
        printf("{\"status\":\"resume_failed\",\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%lu}\n",
               (qOk && activeRem == 0) ? "true" : "false", (unsigned long)activeRem);
        return 0;
    }

    HANDLE waitHandles[2] = { pi.hProcess, hAbortEvent };
    DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, timeoutMs == 0 ? INFINITE : timeoutMs);

    int timedOut = (waitResult == WAIT_TIMEOUT);
    int aborted = (waitResult == WAIT_OBJECT_0 + 1);

    /* 6. Always terminate the entire Job Object on exit/abort/timeout to reap all descendants */
    TerminateJobObject(hJob, 1);
    WaitForSingleObject(pi.hProcess, 5000);

    /* Poll JobObjectBasicAccountingInformation until ActiveProcesses == 0 */
    BOOL queryOk = FALSE;
    DWORD activeRemaining = 999;
    for (int attempt = 0; attempt < 500; attempt++) {
        activeRemaining = query_active_processes(hJob, &queryOk);
        if (queryOk && activeRemaining == 0) {
            break;
        }
        Sleep(10);
    }
    BOOL cleanupConfirmed = (queryOk && activeRemaining == 0);

    /* Wait for stdout/stderr collector threads to drain closed pipes */
    WaitForSingleObject(hOutThread, 3000);
    WaitForSingleObject(hErrThread, 3000);
    CloseHandle(hOutThread);
    CloseHandle(hErrThread);
    CloseHandle(hOutRead);
    CloseHandle(hErrRead);

    DWORD childExitCode = 1;
    GetExitCodeProcess(pi.hProcess, &childExitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hJob);

    if (pidFileLen > 0 && cleanupConfirmed) {
        char doneBuf[64];
        snprintf(doneBuf, sizeof(doneBuf), "%lu:CLEANED", (unsigned long)pi.dwProcessId);
        write_file_atomic_text((const char *)pidFileUtf8, doneBuf);
    }

    if (InterlockedCompareExchange(&watchdog.hostDisconnected, 0, 0) != 0) {
        /* Host is already gone; exit cleanly after confirming job teardown */
        return 0;
    }

    const char *statusStr = "completed";
    if (InterlockedCompareExchange(&outCollector.overflowed, 0, 0) != 0) {
        statusStr = "stdout_overflow";
    } else if (InterlockedCompareExchange(&errCollector.overflowed, 0, 0) != 0) {
        statusStr = "stderr_overflow";
    } else if (InterlockedCompareExchange(&watchdog.cancelRequested, 0, 0) != 0) {
        statusStr = "cancelled";
    } else if (timedOut) {
        statusStr = "timed_out";
    } else if (aborted) {
        statusStr = "aborted";
    }

    char *stdoutB64 = base64_encode(outCollector.buffer ? outCollector.buffer : (const uint8_t *)"", outCollector.length);
    char *stderrB64 = base64_encode(errCollector.buffer ? errCollector.buffer : (const uint8_t *)"", errCollector.length);

    printf("{\"status\":\"%s\",\"exitCode\":%lu,\"childPid\":%lu,\"stdoutBytes\":%zu,\"stderrBytes\":%zu,\"cleanupConfirmed\":%s,\"activeProcessesRemaining\":%lu,\"stdoutB64\":\"%s\",\"stderrB64\":\"%s\"}\n",
           statusStr,
           (unsigned long)childExitCode,
           (unsigned long)pi.dwProcessId,
           outCollector.length,
           errCollector.length,
           cleanupConfirmed ? "true" : "false",
           (unsigned long)activeRemaining,
           stdoutB64 ? stdoutB64 : "",
           stderrB64 ? stderrB64 : "");
    fflush(stdout);

    free(stdoutB64);
    free(stderrB64);
    free(outCollector.buffer);
    free(errCollector.buffer);
    return 0;
}
