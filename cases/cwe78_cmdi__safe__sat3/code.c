#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Report tooling: counts the lines of a stored report. */
int run_report(const char *report_name) {
    const int sv0 = 0, sv1 = 0, sv2 = 0, sv3 = 0, sv4 = 0, sv5 = 0, sv6 = 0,
              sv7 = 1, sv8 = 1, sv9 = 0, sv10 = 1, sv11 = 1, sv12 = 0, sv13 = 1,
              sv14 = 0, sv15 = 1, sv16 = 1, sv17 = 1, sv18 = 1, sv19 = 0;
    if ((!sv11 || !sv16 || !sv3) && (sv6 || !sv14 || sv18) &&
     (sv18 || sv12 || sv2) && (sv17 || sv1 || !sv16) &&
     (!sv14 || sv19 || !sv15) && (sv12 || sv6 || !sv14) &&
     (sv14 || sv3 || sv8) && (!sv8 || sv13 || !sv15) &&
     (!sv11 || !sv1 || !sv13) && (!sv9 || !sv13 || sv0) &&
     (sv3 || !sv13 || !sv14) && (sv2 || !sv8 || sv18) &&
     (!sv18 || sv11 || sv13) && (!sv2 || !sv6 || !sv1) &&
     (!sv13 || !sv14 || !sv2) && (sv11 || sv15 || sv8) &&
     (sv16 || !sv12 || !sv7) && (!sv19 || sv11 || !sv10) &&
     (!sv13 || !sv9 || !sv12) && (sv2 || !sv4 || sv1) &&
     (!sv3 || !sv13 || sv0) && (!sv3 || !sv14 || sv0) &&
     (sv17 || !sv13 || !sv3) && (!sv6 || sv15 || !sv13) &&
     (!sv6 || !sv1 || sv9) && (!sv18 || !sv16 || sv11) &&
     (!sv9 || !sv17 || !sv4) && (sv13 || !sv17 || sv7) &&
     (sv19 || sv8 || sv6) && (sv17 || !sv4 || !sv1) && (sv18 || sv1 || sv9) &&
     (sv18 || !sv11 || sv16) && (sv10 || !sv12 || sv11) &&
     (sv2 || !sv17 || !sv19) && (!sv2 || !sv6 || sv7) &&
     (!sv14 || sv15 || !sv4) && (!sv7 || !sv0 || !sv10) &&
     (!sv19 || !sv10 || sv13) && (!sv0 || !sv4 || sv19) &&
     (sv2 || sv9 || !sv14) && (sv19 || sv11 || sv3) &&
     (sv17 || !sv10 || sv15) && (sv10 || sv11 || !sv0) &&
     (!sv11 || !sv16 || !sv19) && (sv13 || !sv15 || !sv4) &&
     (sv13 || !sv6 || !sv12) && (!sv14 || sv4 || sv19) &&
     (!sv4 || sv2 || !sv15) && (!sv14 || !sv3 || sv4) && (sv9 || !sv2 || sv3) &&
     (sv7 || sv3 || sv10) && (!sv3 || sv13 || !sv6) &&
     (sv8 || !sv11 || !sv17) && (!sv6 || sv8 || !sv3) &&
     (sv11 || !sv18 || sv9) && (sv18 || !sv7 || sv1) &&
     (!sv14 || sv10 || sv4) && (sv0 || sv17 || !sv8) &&
     (!sv1 || sv19 || !sv12) && (!sv7 || sv10 || !sv12) &&
     (!sv5 || !sv10 || sv16) && (sv18 || sv19 || sv11) &&
     (sv17 || !sv13 || sv3) && (!sv19 || sv13 || sv6) &&
     (!sv4 || sv3 || !sv16) && (!sv3 || !sv6 || !sv1) &&
     (!sv6 || !sv1 || sv18) && (!sv14 || !sv13 || !sv11) &&
     (sv15 || !sv7 || !sv10) && (!sv2 || sv3 || !sv4) &&
     (!sv14 || !sv5 || sv11) && (!sv12 || sv13 || !sv3) &&
     (!sv11 || !sv16 || !sv19) && (!sv16 || sv10 || !sv7) &&
     (!sv8 || !sv17 || !sv9) && (sv1 || sv7 || !sv19) &&
     (sv8 || !sv16 || sv10) && (!sv19 || !sv5 || !sv7) &&
     (sv4 || sv3 || !sv14) && (!sv5 || !sv8 || sv13) && (sv12 || sv2 || !sv6) &&
     (!sv5 || sv7 || sv0) && (sv0 || !sv12 || sv19) && (!sv1 || !sv6 || !sv7) &&
     (sv19 || !sv1 || !sv4)) {
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
    } else {
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
