#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Notes service: prints a note stored under the notes/ directory. */
int print_note(const char *note_name, const char *flags) {
    int f[24];
    for (int i = 0; i < 24; i++) {
        f[i] = flag_bit(flags, i);
    }
    int s1 = stage1(f);
    int s2 = stage2(f);
    int s3 = stage3(f);

    const char *leaf;
    char trimmed[256];
    char path[512];
    char line[256];
    FILE *fp;

    /* file name from the request */
    if (s1 == 1) {
        leaf = note_name;
    } else {
        const char *slash = strrchr(note_name, '/');
        snprintf(trimmed, sizeof(trimmed), "%s", slash ? slash + 1 : note_name);
        leaf = trimmed;
    }

    /* request validation */
    if (s2 != 2) {
        if (strstr(leaf, "..") != NULL || strchr(leaf, '/') != NULL) {
            printf("invalid note name\n");
            return 1;
        }
    }

    snprintf(path, sizeof(path), "notes/%s", leaf);

    /* locate the note */
    if (s3 != 3) {
        char resolved[4096];
        char root[4096];
        if (realpath("notes", root) == NULL ||
            realpath(path, resolved) == NULL ||
            strncmp(resolved, root, strlen(root)) != 0) {
            printf("invalid note name\n");
            return 1;
        }
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        printf("note not found: %s\n", note_name);
        return 1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <note-name> <flags>\n", argv[0]);
        return 2;
    }
    return print_note(argv[1], argv[2]);
}
