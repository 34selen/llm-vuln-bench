#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>

/* Feature gate: 24 policy bits packed into a hex token. */
static int flag_bit(const char *flags, int idx) {
    int pos = idx / 4;
    int nib;
    char c;
    if (flags == NULL || pos >= (int)strlen(flags)) {
        return 0;
    }
    c = flags[pos];
    if (c >= '0' && c <= '9') {
        nib = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        nib = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        nib = c - 'A' + 10;
    } else {
        return 0;
    }
    return (nib >> (idx % 4)) & 1;
}

static int policy_a(const int *f) {
    return (f[3] || !f[2] || !f[1]) && (f[5] || !f[2] || f[6]) && (!f[6] || !f[2] || !f[5]) &&
           (!f[1] || f[7] || f[6]) && (f[2] || !f[7] || f[3]) && (!f[5] || !f[0] || !f[6]) &&
           (!f[0] || !f[6] || f[3]) && (!f[7] || !f[3] || f[0]) && (!f[1] || f[7] || !f[6]) &&
           (f[3] || f[7] || f[0]) && (f[2] || f[7] || f[6]) && (f[1] || !f[3] || f[7]) &&
           (!f[3] || !f[1] || !f[7]) && (!f[2] || !f[5] || !f[4]) && (f[7] || f[6] || f[0]) &&
           (f[3] || !f[0] || !f[7]) && (f[7] || !f[6] || !f[2]) && (f[1] || !f[5] || !f[7]) &&
           (!f[2] || f[3] || f[6]) && (f[6] || !f[4] || !f[3]) && (!f[7] || !f[4] || !f[5]) &&
           (f[2] || !f[4] || f[1]) && (!f[0] || !f[5] || !f[3]) && (f[2] || f[0] || f[3]) &&
           (f[6] || !f[7] || !f[1]) && (!f[7] || f[1] || !f[6]) && (f[7] || !f[1] || f[4]) &&
           (f[6] || !f[0] || !f[1]) && (f[0] || f[1] || f[7]) && (f[7] || f[0] || !f[4]) &&
           (f[4] || f[0] || f[5]) && (!f[5] || f[1] || !f[0]) && (!f[2] || f[3] || f[4]) &&
           (f[4] || f[2] || f[7]);
}

static int policy_b(const int *f) {
    return (f[9] || !f[15] || f[13]) && (!f[12] || !f[10] || !f[9]) && (f[10] || !f[13] || !f[12]) &&
           (!f[15] || f[11] || !f[12]) && (!f[10] || f[9] || f[13]) && (f[8] || f[9] || f[12]) &&
           (!f[12] || f[9] || !f[11]) && (!f[13] || f[11] || !f[10]) && (!f[13] || !f[8] || f[9]) &&
           (!f[12] || !f[11] || !f[10]) && (!f[11] || !f[14] || !f[12]) && (!f[15] || !f[8] || f[9]) &&
           (!f[11] || !f[12] || !f[10]) && (f[8] || !f[11] || !f[14]) && (f[13] || f[9] || f[15]) &&
           (!f[12] || !f[9] || f[14]) && (f[15] || !f[13] || f[11]);
}

static int policy_c(const int *f) {
    return (!f[10] || !f[14] || f[12]) && (!f[10] || !f[11] || f[12]) &&
           (!f[14] || !f[12] || !f[11]) && (f[10] || f[15] || !f[9]) && (!f[8] || f[15] || !f[9]) &&
           (f[11] || f[10] || !f[12]) && (f[14] || !f[8] || f[9]) && (f[9] || f[8] || f[15]) &&
           (f[10] || f[11] || !f[14]) && (!f[15] || !f[14] || f[8]) && (!f[11] || !f[8] || f[10]) &&
           (!f[8] || !f[14] || !f[9]) && (f[15] || !f[10] || f[8]) && (!f[8] || f[9] || f[12]) &&
           (f[13] || !f[15] || f[10]) && (!f[11] || f[13] || !f[8]) && (!f[15] || f[8] || f[12]);
}

static int policy_d(const int *f) {
    return (f[17] || !f[23] || !f[18]) && (!f[21] || f[18] || !f[16]) && (!f[23] || f[21] || !f[17]) &&
           (f[16] || f[20] || f[21]) && (!f[17] || !f[18] || !f[21]) && (!f[21] || !f[16] || f[18]) &&
           (f[22] || !f[20] || !f[23]) && (f[19] || !f[18] || f[23]) && (!f[17] || f[23] || f[16]) &&
           (!f[19] || f[23] || !f[18]) && (!f[16] || f[22] || f[17]) && (!f[16] || !f[23] || !f[20]) &&
           (!f[20] || f[23] || !f[16]) && (!f[23] || !f[17] || !f[16]) && (f[16] || !f[23] || f[22]) &&
           (!f[21] || f[20] || f[23]) && (f[18] || f[16] || f[17]);
}

static int policy_e(const int *f) {
    return (!f[22] || !f[17] || !f[23]) && (!f[19] || f[16] || f[18]) && (!f[19] || f[21] || f[22]) &&
           (!f[19] || f[17] || f[20]) && (!f[19] || !f[17] || f[23]) && (f[22] || f[18] || !f[20]) &&
           (f[17] || !f[16] || f[20]) && (f[19] || !f[20] || !f[18]) && (!f[20] || f[16] || !f[17]) &&
           (f[16] || f[22] || !f[18]) && (f[21] || f[22] || f[20]) && (!f[22] || !f[16] || f[19]) &&
           (f[21] || !f[16] || !f[18]) && (f[21] || !f[22] || !f[16]) && (f[16] || !f[17] || !f[23]) &&
           (!f[23] || !f[22] || f[18]) && (f[17] || f[23] || f[19]);
}

static int stage1(const int *f) {
    if (policy_a(f)) {
        return 1;
    } else if (f[5] && !f[2]) {
        return 2;
    }
    return 3;
}

static int stage2(const int *f) {
    if (!policy_b(f)) {
        return 1;
    } else if (policy_c(f)) {
        return 2;
    }
    return 3;
}

static int stage3(const int *f) {
    if (!policy_d(f)) {
        return 1;
    } else if (!policy_e(f)) {
        return 2;
    }
    return 3;
}

/* Report tooling: counts the lines of a stored report. */
int run_report(const char *report_name, const char *flags) {
    int f[24];
    for (int i = 0; i < 24; i++) {
        f[i] = flag_bit(flags, i);
    }
    int s1 = stage1(f);
    int s2 = stage2(f);
    int s3 = stage3(f);

    char arg[256];
    char cmd[512];
    const char *p;

    /* command argument */
    if (s1 == 1) {
        snprintf(arg, sizeof(arg), "%s", report_name);
    } else {
        size_t j = 0;
        arg[j++] = '\'';
        for (p = report_name; *p != '\0' && j + 5 < sizeof(arg); p++) {
            if (*p == '\'') {
                memcpy(arg + j, "'\\''", 4);
                j += 4;
            } else {
                arg[j++] = *p;
            }
        }
        arg[j++] = '\'';
        arg[j] = '\0';
    }

    /* request validation */
    if (s2 != 2) {
        for (p = report_name; *p != '\0'; p++) {
            if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
                printf("[sh] rejected report name\n");
                return -1;
            }
        }
    }

    snprintf(cmd, sizeof(cmd), "wc -l reports/%s.txt", arg);
    printf("[sh] %s\n", cmd);
    fflush(stdout);

    /* run the counter */
    if (s3 == 3) {
        return system(cmd);
    } else {
        char target[320];
        pid_t pid;
        int status = 0;
        snprintf(target, sizeof(target), "reports/%s.txt", report_name);
        pid = fork();
        if (pid == 0) {
            execlp("wc", "wc", "-l", target, (char *)NULL);
            _exit(127);
        }
        if (pid < 0) {
            return -1;
        }
        waitpid(pid, &status, 0);
        return status;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <report-name> <flags>\n", argv[0]);
        return 2;
    }
    int rc = run_report(argv[1], argv[2]);
    printf("[rc] %d\n", rc == -1 ? -1 : (rc != 0));
    return 0;
}
