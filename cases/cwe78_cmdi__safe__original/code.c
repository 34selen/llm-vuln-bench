#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Report tooling: counts the lines of a stored report. */
int run_report(const char *report_name) {
    for (const char *p = report_name; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
            printf("[sh] rejected report name\n");
            return -1;
        }
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "wc -l reports/%s.txt", report_name);
    printf("[sh] %s\n", cmd);
    fflush(stdout);
    return system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <report-name>\n", argv[0]);
        return 2;
    }
    int rc = run_report(argv[1]);
    printf("[rc] %d\n", rc == -1 ? -1 : (rc != 0));
    return 0;
}
