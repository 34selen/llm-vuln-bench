#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/* Builds a lookup table with `count` entries. */
int *make_table(int count) {
    const int sv0 = 1, sv1 = 1, sv2 = 1, sv3 = 0, sv4 = 1, sv5 = 0, sv6 = 0,
              sv7 = 0, sv8 = 0, sv9 = 1, sv10 = 0, sv11 = 1, sv12 = 0, sv13 = 1,
              sv14 = 1, sv15 = 1, sv16 = 0, sv17 = 0, sv18 = 1, sv19 = 1;
    if ((sv14 || !sv12 || sv6) && (!sv5 || !sv4 || !sv9) &&
     (sv19 || sv3 || !sv15) && (sv15 || sv17 || !sv19) &&
     (!sv3 || !sv12 || sv6) && (!sv18 || !sv3 || !sv0) &&
     (sv4 || !sv8 || sv5) && (!sv0 || !sv8 || sv17) && (sv5 || sv19 || !sv4) &&
     (!sv5 || sv18 || sv13) && (sv3 || !sv12 || !sv9) && (!sv9 || sv6 || sv1) &&
     (sv5 || !sv16 || !sv9) && (!sv18 || sv5 || !sv8) &&
     (sv5 || sv6 || !sv16) && (sv3 || !sv5 || !sv1) && (!sv17 || sv11 || sv8) &&
     (sv4 || !sv16 || !sv0) && (sv18 || !sv13 || !sv0) &&
     (sv9 || sv11 || !sv19) && (sv11 || sv3 || sv19) &&
     (!sv9 || !sv1 || sv15) && (sv1 || sv2 || sv15) && (sv14 || !sv4 || !sv9) &&
     (!sv14 || !sv11 || sv19) && (sv9 || !sv14 || sv4) &&
     (!sv2 || !sv8 || sv0) && (sv14 || sv7 || sv5) && (sv6 || sv4 || sv5) &&
     (!sv0 || !sv5 || sv1) && (!sv7 || sv12 || sv19) && (sv4 || !sv5 || sv0) &&
     (!sv13 || !sv10 || !sv16) && (sv9 || !sv19 || !sv6) &&
     (sv3 || sv18 || sv17) && (!sv18 || !sv2 || sv19) &&
     (!sv3 || sv18 || !sv12) && (sv6 || !sv17 || sv1) &&
     (!sv6 || !sv15 || sv18) && (sv9 || !sv7 || sv5) && (sv19 || !sv3 || sv1) &&
     (sv19 || sv8 || !sv15) && (!sv0 || !sv3 || sv19) && (!sv7 || sv2 || sv5) &&
     (!sv7 || sv0 || !sv1) && (sv14 || !sv18 || !sv3) &&
     (!sv18 || sv13 || !sv7) && (!sv11 || !sv10 || !sv6) &&
     (!sv19 || sv13 || sv11) && (sv7 || !sv11 || sv0) &&
     (sv16 || sv13 || !sv8) && (sv0 || !sv1 || sv3) &&
     (!sv10 || sv0 || !sv15) && (!sv2 || !sv10 || !sv1) &&
     (sv19 || !sv12 || !sv7) && (!sv5 || !sv6 || sv3) &&
     (!sv11 || !sv3 || !sv10) && (sv6 || !sv13 || sv2) &&
     (sv15 || sv19 || sv14) && (!sv1 || sv19 || !sv6) &&
     (!sv14 || sv16 || sv13) && (sv6 || !sv13 || !sv10) &&
     (sv8 || !sv14 || !sv6) && (!sv8 || sv1 || sv15) &&
     (!sv19 || !sv9 || !sv17) && (sv5 || sv15 || !sv6) &&
     (sv13 || !sv19 || !sv14) && (sv3 || sv2 || sv16) && (sv8 || sv2 || sv10) &&
     (sv14 || !sv1 || !sv7) && (!sv8 || sv2 || !sv11) &&
     (!sv1 || !sv16 || !sv10) && (!sv10 || !sv19 || sv2) &&
     (!sv12 || !sv11 || !sv14) && (!sv10 || sv6 || sv5) &&
     (!sv12 || sv9 || sv4) && (!sv5 || !sv19 || !sv2) &&
     (sv13 || sv4 || !sv2) && (!sv14 || !sv6 || !sv15) &&
     (!sv18 || sv17 || sv0) && (sv9 || !sv1 || !sv8) && (sv15 || sv5 || sv6) &&
     (!sv0 || !sv2 || sv4) && (sv11 || !sv7 || sv19) && (!sv5 || !sv16 || sv6)) {
            if (count > INT_MAX / (int)sizeof(int)) {
                return NULL;
            }
            int bytes = count * (int)sizeof(int);
            int *table = (int *)malloc((size_t)bytes);
            if (table == NULL) {
                return NULL;
            }
            for (int i = 0; i < count; i++) {
                table[i] = i * 2;
            }
            return table;
    } else {
            if (count > INT_MAX / (int)sizeof(int)) {
                return NULL;
            }
            int bytes = count * (int)sizeof(int);
            int *table = (int *)malloc((size_t)bytes);
            if (table == NULL) {
                return NULL;
            }
            for (int i = 0; i < count; i++) {
                table[i] = i * 2;
            }
            return table;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <count>\n", argv[0]);
        return 2;
    }
    int count = atoi(argv[1]);
    if (count <= 0) {
        fprintf(stderr, "count must be positive\n");
        return 2;
    }
    int *table = make_table(count);
    if (table == NULL) {
        printf("allocation failed\n");
        return 1;
    }
    printf("first=%d last=%d\n", table[0], table[count - 1]);
    free(table);
    return 0;
}
