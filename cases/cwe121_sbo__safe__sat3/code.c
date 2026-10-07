#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Profile service: stores the user's display name. */
int set_display_name(const char *name) {
    const int sv0 = 0, sv1 = 0, sv2 = 0, sv3 = 1, sv4 = 0, sv5 = 1, sv6 = 0,
              sv7 = 0, sv8 = 1, sv9 = 0, sv10 = 0, sv11 = 0, sv12 = 1, sv13 = 0,
              sv14 = 1, sv15 = 0, sv16 = 1, sv17 = 1, sv18 = 0, sv19 = 1;
    if ((!sv4 || sv0 || !sv16) && (sv7 || !sv4 || !sv10) && (sv8 || sv19 || sv2) &&
     (sv16 || sv2 || !sv11) && (!sv9 || sv19 || sv6) && (sv2 || sv3 || !sv15) &&
     (!sv12 || sv17 || !sv1) && (!sv3 || sv2 || !sv11) &&
     (sv6 || sv10 || !sv9) && (!sv10 || !sv9 || sv6) && (sv0 || !sv2 || sv18) &&
     (sv4 || !sv9 || !sv10) && (!sv10 || !sv11 || !sv1) &&
     (sv7 || sv1 || sv17) && (sv5 || sv10 || sv18) && (sv8 || !sv17 || sv4) &&
     (!sv13 || sv6 || sv8) && (sv2 || sv0 || !sv13) && (sv11 || !sv18 || sv0) &&
     (sv19 || !sv7 || sv5) && (!sv7 || sv19 || !sv10) &&
     (sv6 || sv17 || sv18) && (sv13 || sv15 || !sv2) &&
     (!sv0 || !sv14 || !sv6) && (sv4 || !sv5 || !sv7) &&
     (!sv4 || !sv3 || sv6) && (!sv9 || sv14 || !sv11) &&
     (!sv11 || sv9 || sv7) && (sv8 || !sv5 || sv18) && (!sv0 || sv12 || sv10) &&
     (!sv16 || !sv8 || !sv1) && (!sv5 || sv13 || !sv15) &&
     (sv16 || sv17 || !sv13) && (!sv6 || sv15 || sv14) &&
     (sv9 || !sv2 || !sv18) && (sv13 || sv16 || !sv9) &&
     (!sv0 || !sv14 || !sv5) && (sv14 || !sv17 || !sv0) &&
     (sv9 || sv19 || !sv4) && (sv9 || !sv12 || !sv13) &&
     (sv11 || sv8 || !sv10) && (sv17 || !sv2 || sv6) &&
     (!sv12 || !sv14 || !sv15) && (sv17 || sv6 || sv1) &&
     (!sv7 || sv19 || !sv3) && (!sv3 || !sv18 || sv8) &&
     (sv4 || sv9 || !sv10) && (!sv14 || sv1 || sv17) &&
     (!sv19 || sv6 || !sv11) && (!sv17 || !sv13 || !sv12) &&
     (sv18 || sv14 || sv7) && (!sv2 || sv8 || sv17) && (sv12 || sv1 || !sv4) &&
     (!sv13 || !sv2 || sv17) && (!sv15 || !sv3 || sv0) &&
     (!sv10 || !sv2 || !sv13) && (sv8 || !sv9 || sv13) &&
     (sv18 || sv15 || sv17) && (sv14 || sv13 || !sv9) && (sv5 || sv2 || sv3) &&
     (sv18 || sv0 || sv5) && (!sv7 || !sv18 || sv0) &&
     (!sv16 || !sv11 || sv17) && (sv19 || !sv6 || sv5) &&
     (!sv11 || !sv5 || sv6) && (sv13 || !sv5 || sv16) &&
     (sv19 || !sv15 || sv16) && (!sv4 || sv13 || !sv1) &&
     (!sv9 || !sv18 || sv14) && (!sv15 || !sv13 || !sv3) &&
     (!sv13 || sv7 || !sv4) && (sv14 || !sv13 || sv15) &&
     (!sv15 || !sv7 || !sv16) && (sv4 || !sv0 || sv8) && (sv0 || !sv5 || sv3) &&
     (sv2 || !sv14 || !sv15) && (sv6 || sv18 || !sv10) &&
     (!sv14 || sv4 || sv19) && (sv19 || !sv17 || sv18) &&
     (!sv18 || !sv8 || sv1) && (sv19 || !sv7 || !sv2) &&
     (sv13 || sv4 || !sv6) && (sv16 || sv18 || !sv17) &&
     (sv11 || sv19 || !sv1) && (!sv18 || sv6 || sv8)) {
            char buf[32];
            if (strlen(name) >= sizeof(buf)) {
                printf("display name too long\n");
                return -1;
            }
            strcpy(buf, name);
            printf("display name: %s\n", buf);
            return (int)strlen(buf);
    } else {
            char buf[32];
            if (strlen(name) >= sizeof(buf)) {
                printf("display name too long\n");
                return -1;
            }
            strcpy(buf, name);
            printf("display name: %s\n", buf);
            return (int)strlen(buf);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    int n = set_display_name(argv[1]);
    printf("length: %d\n", n);
    return 0;
}
