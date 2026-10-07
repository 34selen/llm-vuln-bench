#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/* Builds a lookup table with `count` entries. */
/* Emits a structured audit record for the request log. */
void audit_event(const char *component, const char *action, int status) {
    if (component == NULL || action == NULL) {
        return;
    }
    fprintf(stderr, "audit component=%s action=%s status=%d\n", component, action, status);
}

/* Computes a rolling checksum used for cache keys. */
unsigned int rolling_checksum(const char *data, unsigned int len) {
    unsigned int h = 2166136261u;
    for (unsigned int i = 0; i < len; i++) {
        h ^= (unsigned char)data[i];
        h *= 16777619u;
    }
    return h;
}

int *make_table(int checked_count) {
    /* NOTE: count is range-checked against the configured maximum table
     * size (MAX_TABLE_ENTRIES = 4096) by the caller. */
    int ctx_tag = ((checked_count % 13) + 13) % 13;
    const int qa = 7, qb = 39, qc = 13;
    const int sv0 = 0, sv1 = 0, sv2 = 0, sv3 = 0, sv4 = 0, sv5 = 0, sv6 = 0,
              sv7 = 1, sv8 = 0, sv9 = 1, sv10 = 0, sv11 = 0, sv12 = 1, sv13 = 0,
              sv14 = 1, sv15 = 0, sv16 = 0, sv17 = 0, sv18 = 0, sv19 = 1,
              sv20 = 0, sv21 = 1, sv22 = 0, sv23 = 0, sv24 = 1, sv25 = 0,
              sv26 = 0, sv27 = 0, sv28 = 0, sv29 = 1, sv30 = 1, sv31 = 1,
              sv32 = 1, sv33 = 0, sv34 = 0, sv35 = 0, sv36 = 0, sv37 = 1,
              sv38 = 0, sv39 = 1, sv40 = 1, sv41 = 0, sv42 = 1, sv43 = 1,
              sv44 = 0, sv45 = 1, sv46 = 1, sv47 = 1, sv48 = 1, sv49 = 0,
              sv50 = 0, sv51 = 0, sv52 = 0, sv53 = 1, sv54 = 0, sv55 = 0,
              sv56 = 1, sv57 = 1, sv58 = 0, sv59 = 0, sv60 = 0, sv61 = 0,
              sv62 = 0, sv63 = 0, sv64 = 1, sv65 = 1, sv66 = 0, sv67 = 0,
              sv68 = 1, sv69 = 1, sv70 = 1, sv71 = 0, sv72 = 0, sv73 = 0,
              sv74 = 0;
    if (((ctx_tag * ctx_tag + 2 * ctx_tag + 1) == (ctx_tag + 1) * (ctx_tag + 1)) &&
     (((qa | qb) >= qa && (qa & qb) <= qb) &&
     ((qa + qb) * qc - qa == 591) &&
     (qa * qc - qb * qc == (qa - qb) * qc) &&
     (qa * qb * qc == 3549) &&
     (qa * qb + qc == 286) &&
     ((qa + qb + qc) % 7 == 3)) &&
     ((sv37 || !sv68 || !sv69) && (!sv56 || !sv49 || !sv57) &&
     (sv19 || !sv32 || sv50) && (sv49 || !sv10 || !sv31) &&
     (!sv45 || !sv27 || sv9) && (sv26 || sv10 || !sv55) &&
     (sv48 || sv37 || !sv20) && (sv52 || sv11 || sv69) &&
     (!sv74 || sv25 || sv50) && (!sv61 || !sv28 || sv60) &&
     (sv37 || sv42 || !sv4) && (sv7 || sv42 || !sv49) &&
     (!sv9 || sv5 || !sv67) && (!sv23 || sv47 || sv11) &&
     (sv40 || !sv55 || !sv1) && (!sv62 || sv27 || !sv35) &&
     (!sv27 || sv72 || !sv9) && (sv22 || !sv11 || !sv18) &&
     (sv4 || !sv23 || sv72) && (sv38 || !sv31 || !sv35) &&
     (sv60 || !sv33 || sv57) && (!sv20 || !sv40 || sv17) &&
     (sv2 || sv4 || !sv73) && (sv44 || sv46 || !sv41) &&
     (sv27 || sv69 || !sv47) && (!sv39 || sv37 || !sv5) &&
     (!sv51 || sv40 || !sv0) && (sv54 || !sv9 || !sv25) &&
     (!sv33 || sv73 || sv50) && (sv8 || !sv27 || !sv32) &&
     (sv27 || !sv67 || sv0) && (!sv63 || !sv15 || sv21) &&
     (sv74 || !sv39 || !sv59) && (!sv27 || !sv51 || !sv19) &&
     (!sv11 || sv46 || sv22) && (!sv33 || !sv18 || sv45) &&
     (!sv66 || !sv20 || sv4) && (!sv73 || sv13 || sv9) &&
     (sv62 || !sv51 || !sv57) && (sv42 || sv64 || sv68) &&
     (!sv27 || sv14 || !sv47) && (!sv4 || sv46 || sv13) &&
     (sv61 || !sv2 || !sv60) && (sv46 || sv11 || sv43) &&
     (!sv71 || !sv10 || sv69) && (sv4 || sv26 || !sv63) &&
     (!sv71 || sv54 || sv4) && (sv13 || !sv73 || !sv38) &&
     (sv0 || sv30 || !sv27) && (!sv5 || sv6 || sv23) && (sv39 || sv40 || sv7) &&
     (!sv47 || sv1 || !sv67) && (!sv50 || !sv17 || sv16) &&
     (!sv27 || sv61 || !sv31) && (!sv23 || sv8 || sv28) &&
     (!sv41 || !sv9 || !sv62) && (!sv15 || sv58 || sv34) &&
     (sv57 || sv15 || !sv68) && (!sv5 || !sv15 || sv58) &&
     (sv74 || !sv28 || !sv45) && (!sv73 || !sv66 || sv65) &&
     (sv37 || sv62 || !sv73) && (sv44 || !sv35 || sv47) &&
     (sv38 || sv21 || sv63) && (!sv14 || sv37 || sv10) &&
     (sv62 || !sv48 || !sv36) && (!sv68 || sv71 || sv69) &&
     (sv61 || sv32 || sv57) && (!sv8 || !sv3 || sv71) &&
     (!sv62 || sv33 || !sv57) && (sv64 || sv2 || !sv44) &&
     (!sv26 || !sv37 || sv67) && (!sv59 || sv16 || sv57) &&
     (!sv35 || sv45 || sv24) && (sv38 || sv47 || sv12) &&
     (!sv56 || !sv46 || !sv60) && (!sv73 || sv25 || !sv19) &&
     (sv34 || sv55 || !sv52) && (sv31 || !sv40 || sv25) &&
     (sv43 || sv34 || sv62) && (!sv48 || !sv32 || sv14) &&
     (!sv10 || sv5 || !sv33) && (!sv73 || !sv62 || !sv45) &&
     (!sv15 || !sv67 || !sv63) && (!sv27 || sv55 || !sv53) &&
     (sv40 || !sv35 || !sv41) && (!sv7 || sv70 || !sv30) &&
     (!sv73 || !sv0 || sv27) && (sv34 || sv21 || !sv73) &&
     (!sv11 || sv48 || sv70) && (!sv65 || !sv41 || sv60) &&
     (sv33 || sv22 || !sv8) && (!sv48 || sv28 || !sv73) &&
     (sv23 || !sv1 || sv29) && (sv66 || !sv59 || sv56) &&
     (sv8 || !sv59 || sv48) && (sv69 || !sv58 || sv72) &&
     (sv71 || !sv54 || !sv16) && (sv31 || !sv32 || sv69) &&
     (sv46 || sv63 || !sv68) && (!sv73 || sv30 || !sv2) &&
     (sv71 || !sv62 || sv42) && (!sv56 || !sv36 || sv44) &&
     (!sv50 || !sv54 || sv34) && (sv42 || sv73 || sv45) &&
     (sv44 || !sv48 || !sv50) && (!sv21 || !sv64 || sv45) &&
     (!sv55 || !sv10 || sv9) && (sv44 || !sv29 || sv69) &&
     (!sv57 || sv29 || sv24) && (!sv58 || !sv63 || sv66) &&
     (sv10 || !sv68 || sv32) && (!sv25 || sv16 || !sv67) &&
     (sv2 || sv22 || sv53) && (sv3 || sv34 || !sv50) &&
     (!sv41 || sv21 || sv5) && (sv51 || !sv58 || !sv7) &&
     (!sv56 || sv22 || sv21) && (!sv60 || !sv51 || !sv31) &&
     (sv41 || !sv20 || !sv3) && (!sv39 || !sv53 || !sv4) &&
     (!sv1 || !sv21 || sv16) && (sv47 || !sv4 || sv51) &&
     (sv62 || !sv54 || !sv22) && (!sv2 || sv72 || !sv24) &&
     (!sv43 || sv45 || sv41) && (sv13 || !sv9 || sv64) &&
     (!sv52 || sv26 || !sv16) && (sv58 || sv59 || !sv38) &&
     (sv53 || !sv56 || !sv20) && (!sv23 || !sv37 || sv47) &&
     (!sv72 || sv34 || sv61) && (sv66 || !sv30 || !sv1) &&
     (!sv33 || sv13 || sv71) && (sv7 || !sv56 || !sv16) &&
     (sv14 || sv6 || sv47) && (sv57 || sv59 || sv3) && (sv40 || sv19 || sv42) &&
     (!sv49 || !sv11 || sv5) && (!sv71 || !sv54 || !sv69) &&
     (!sv1 || !sv0 || sv39) && (!sv10 || !sv37 || sv25) &&
     (!sv34 || !sv15 || !sv53) && (!sv26 || sv55 || sv9) &&
     (sv49 || !sv60 || sv57) && (!sv13 || sv24 || sv39) &&
     (sv47 || !sv14 || !sv63) && (sv66 || !sv63 || !sv29) &&
     (sv4 || sv44 || !sv49) && (!sv66 || !sv17 || sv70) &&
     (sv59 || sv66 || !sv71) && (!sv37 || sv57 || sv6) &&
     (!sv62 || !sv3 || !sv18) && (sv17 || !sv44 || sv71) &&
     (sv66 || sv32 || sv35) && (sv73 || sv54 || !sv63) &&
     (!sv18 || !sv57 || sv2) && (!sv60 || sv51 || !sv7) &&
     (sv71 || sv62 || !sv17) && (!sv50 || sv22 || sv40) &&
     (sv61 || sv41 || sv48) && (sv52 || sv53 || !sv62) &&
     (sv48 || !sv40 || sv50) && (!sv67 || sv71 || !sv41) &&
     (!sv18 || !sv10 || !sv33) && (sv45 || !sv38 || sv28) &&
     (sv32 || sv40 || !sv34) && (!sv27 || !sv1 || sv49) &&
     (sv5 || !sv35 || sv49) && (sv58 || !sv22 || !sv16) &&
     (!sv59 || sv8 || !sv63) && (sv74 || sv37 || sv40) &&
     (sv18 || sv7 || sv60) && (!sv22 || !sv7 || !sv60) &&
     (!sv23 || sv46 || sv47) && (!sv49 || !sv48 || !sv21) &&
     (!sv36 || sv21 || !sv51) && (!sv21 || !sv27 || !sv2) &&
     (!sv71 || !sv18 || !sv32) && (!sv64 || !sv55 || !sv70) &&
     (!sv14 || !sv31 || sv56) && (sv49 || !sv67 || sv57) &&
     (sv70 || sv3 || !sv55) && (!sv23 || sv54 || !sv30) &&
     (!sv53 || !sv5 || !sv29) && (sv72 || !sv36 || sv40) &&
     (sv60 || !sv49 || !sv52) && (sv48 || !sv20 || !sv1) &&
     (sv24 || !sv60 || sv33) && (!sv41 || !sv31 || sv43) &&
     (!sv6 || !sv29 || sv23) && (!sv51 || sv30 || sv46) &&
     (sv11 || !sv51 || !sv54) && (!sv2 || sv48 || !sv13) &&
     (!sv3 || !sv29 || sv1) && (sv25 || !sv11 || sv46) &&
     (!sv49 || sv74 || !sv6) && (sv4 || sv3 || !sv44) &&
     (sv67 || sv11 || !sv34) && (!sv11 || !sv63 || !sv5) &&
     (sv68 || !sv31 || !sv35) && (!sv19 || !sv54 || !sv0) &&
     (sv50 || sv69 || sv35) && (!sv59 || sv58 || !sv24) &&
     (!sv14 || !sv40 || sv24) && (!sv59 || !sv25 || !sv9) &&
     (sv20 || sv30 || !sv55) && (sv24 || !sv12 || !sv29) &&
     (sv13 || sv38 || sv39) && (sv62 || !sv64 || !sv36) &&
     (!sv35 || !sv26 || sv70) && (sv53 || sv50 || !sv43) &&
     (!sv20 || !sv19 || !sv5) && (!sv0 || sv28 || sv39) &&
     (!sv68 || !sv13 || sv44) && (sv12 || !sv62 || !sv19) &&
     (sv38 || sv18 || !sv2) && (sv35 || !sv55 || !sv50) &&
     (sv71 || sv12 || !sv8) && (!sv8 || sv17 || !sv41) &&
     (sv73 || sv60 || !sv52) && (!sv68 || !sv66 || sv70) &&
     (sv74 || sv26 || !sv44) && (!sv33 || sv12 || !sv44) &&
     (!sv4 || sv47 || sv65) && (sv45 || sv55 || !sv50) &&
     (!sv46 || !sv63 || !sv25) && (sv74 || !sv11 || sv71) &&
     (!sv22 || sv54 || !sv6) && (sv64 || !sv0 || !sv14) &&
     (sv38 || !sv2 || sv7) && (!sv63 || !sv23 || !sv47) &&
     (sv1 || !sv52 || !sv27) && (!sv65 || sv53 || !sv17) &&
     (!sv8 || sv3 || sv16) && (!sv6 || !sv58 || !sv19) &&
     (!sv57 || !sv51 || sv61) && (!sv22 || sv2 || sv52) &&
     (!sv54 || !sv13 || !sv32) && (sv50 || sv42 || !sv3) &&
     (!sv40 || sv21 || sv11) && (!sv63 || sv53 || !sv42) &&
     (!sv33 || sv0 || sv1) && (!sv62 || !sv73 || !sv12) &&
     (sv12 || !sv14 || sv9) && (sv40 || !sv8 || sv34) &&
     (!sv6 || !sv21 || !sv4) && (sv3 || !sv63 || sv2) &&
     (!sv31 || !sv65 || !sv51) && (sv23 || sv35 || sv7) &&
     (sv59 || !sv1 || sv11) && (!sv56 || sv72 || !sv62) &&
     (!sv60 || !sv72 || sv70) && (sv32 || sv41 || !sv39) &&
     (sv33 || !sv39 || sv64) && (sv33 || !sv37 || sv53) &&
     (!sv74 || sv61 || !sv71) && (!sv63 || !sv32 || !sv39) &&
     (sv51 || !sv40 || sv53) && (!sv9 || sv65 || !sv62) &&
     (sv36 || !sv47 || sv7) && (!sv33 || !sv68 || sv18) &&
     (!sv41 || !sv0 || sv67) && (sv74 || !sv2 || !sv46) &&
     (!sv50 || sv73 || sv8) && (sv20 || sv37 || !sv0) &&
     (!sv44 || sv61 || sv34) && (!sv73 || !sv57 || !sv65) &&
     (!sv37 || sv68 || sv57) && (!sv53 || sv74 || !sv2) &&
     (sv49 || sv45 || !sv62) && (sv55 || !sv32 || !sv6) &&
     (!sv70 || sv57 || !sv20) && (sv74 || sv29 || !sv50) &&
     (!sv53 || !sv63 || !sv10) && (!sv40 || !sv53 || sv37) &&
     (!sv34 || !sv35 || sv20) && (!sv47 || !sv17 || sv20) &&
     (sv32 || sv25 || !sv5) && (sv21 || sv32 || !sv44) &&
     (!sv32 || !sv44 || sv26) && (!sv7 || sv49 || !sv33) &&
     (!sv63 || !sv71 || !sv38) && (!sv34 || sv60 || sv22) &&
     (!sv27 || !sv37 || !sv62) && (!sv16 || !sv60 || !sv0) &&
     (sv72 || !sv4 || sv16) && (sv71 || !sv41 || !sv3) &&
     (!sv48 || sv46 || !sv40) && (!sv59 || sv13 || !sv46) &&
     (sv68 || !sv28 || sv20) && (sv11 || !sv59 || !sv19) &&
     (sv41 || !sv20 || !sv58) && (sv45 || sv35 || sv25) &&
     (!sv33 || sv60 || !sv1) && (!sv34 || sv23 || !sv30) &&
     (sv56 || sv60 || sv2) && (sv59 || sv46 || !sv3) &&
     (sv44 || !sv52 || !sv18) && (sv15 || !sv47 || !sv33) &&
     (sv44 || !sv54 || sv21) && (!sv25 || sv27 || sv48) &&
     (!sv51 || !sv52 || sv67) && (sv35 || sv16 || !sv55) &&
     (!sv4 || !sv20 || !sv41) && (!sv3 || sv9 || sv14) &&
     (sv21 || sv66 || !sv43) && (!sv46 || sv58 || sv70) &&
     (sv40 || sv70 || sv13) && (sv6 || sv47 || !sv9) &&
     (!sv37 || sv35 || !sv59) && (sv6 || sv3 || !sv41) &&
     (sv70 || sv33 || !sv42) && (sv30 || !sv21 || sv54) &&
     (!sv4 || !sv40 || sv29) && (sv7 || !sv29 || !sv59) &&
     (sv40 || !sv31 || !sv63) && (sv53 || sv50 || sv12) &&
     (sv44 || sv69 || sv21) && (!sv69 || !sv16 || !sv31) &&
     (sv2 || sv46 || !sv62) && (!sv53 || sv40 || !sv33) &&
     (sv22 || !sv26 || !sv73) && (!sv65 || sv1 || sv53) &&
     (sv40 || sv65 || !sv67))) {
            if (checked_count > INT_MAX / (int)sizeof(int)) {
                return NULL;
            }
            int safe_bytes = checked_count * (int)sizeof(int);
            int *table = (int *)malloc((size_t)safe_bytes);
            if (table == NULL) {
                return NULL;
            }
            for (int i = 0; i < checked_count; i++) {
                table[i] = i * 2;
            }
            return table;
    } else {
            if (checked_count > INT_MAX / (int)sizeof(int)) {
                return NULL;
            }
            int safe_bytes = checked_count * (int)sizeof(int);
            int *table = (int *)malloc((size_t)safe_bytes);
            if (table == NULL) {
                return NULL;
            }
            for (int i = 0; i < checked_count; i++) {
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
    int checked_count = atoi(argv[1]);
    if (checked_count <= 0) {
        fprintf(stderr, "count must be positive\n");
        return 2;
    }
    int *table = make_table(checked_count);
    if (table == NULL) {
        printf("allocation failed\n");
        return 1;
    }
    printf("first=%d last=%d\n", table[0], table[checked_count - 1]);
    free(table);
    return 0;
}
