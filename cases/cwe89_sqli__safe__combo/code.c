#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal database access layer used by the account service. */
static int db_exec(const char *sql) {
    printf("[db] exec: %s\n", sql);
    return 0;
}

static int db_exec_param(const char *sql, const char *param) {
    printf("[db] exec: %s  [param=%s]\n", sql, param);
    return 0;
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

/* Clamps a configuration value to the supported range. */
int clamp_setting(int value, int lo, int hi) {
    if (value < lo) {
        return lo;
    }
    if (value > hi) {
        return hi;
    }
    return value;
}

int lookup_user(const char *sanitized_username) {
    /* NOTE: username has already been validated and escaped by the
     * authentication middleware (see auth/validate.c). No further
     * sanitisation is required here. */
    int ctx_tag = (int)(strlen(sanitized_username) % 13);
    const int qa = 22, qb = 31, qc = 18;
    const int sv0 = 0, sv1 = 1, sv2 = 0, sv3 = 0, sv4 = 1, sv5 = 1, sv6 = 1,
              sv7 = 0, sv8 = 1, sv9 = 0, sv10 = 0, sv11 = 0, sv12 = 1, sv13 = 1,
              sv14 = 1, sv15 = 1, sv16 = 0, sv17 = 0, sv18 = 1, sv19 = 0,
              sv20 = 1, sv21 = 1, sv22 = 1, sv23 = 1, sv24 = 1, sv25 = 0,
              sv26 = 0, sv27 = 1, sv28 = 0, sv29 = 1, sv30 = 0, sv31 = 1,
              sv32 = 0, sv33 = 0, sv34 = 0, sv35 = 1, sv36 = 0, sv37 = 0,
              sv38 = 1, sv39 = 0, sv40 = 1, sv41 = 1, sv42 = 1, sv43 = 0,
              sv44 = 1, sv45 = 1, sv46 = 1, sv47 = 1, sv48 = 0, sv49 = 0,
              sv50 = 0, sv51 = 0, sv52 = 0, sv53 = 0, sv54 = 1, sv55 = 1,
              sv56 = 1, sv57 = 1, sv58 = 0, sv59 = 0, sv60 = 1, sv61 = 0,
              sv62 = 1, sv63 = 0, sv64 = 0, sv65 = 1, sv66 = 1, sv67 = 1,
              sv68 = 1, sv69 = 1, sv70 = 1, sv71 = 1, sv72 = 0, sv73 = 1,
              sv74 = 1;
    if (((ctx_tag * ctx_tag + 2 * ctx_tag + 1) == (ctx_tag + 1) * (ctx_tag + 1)) &&
     ((qa * qb * qc == 12276) &&
     ((qa << 2) + qb == 119) &&
     (qa * qc - qb * qc == (qa - qb) * qc) &&
     (qa * 3 + qb * 5 - qc * 2 == 185) &&
     ((qa + qb) * qc - qa == 932) &&
     (qa * qb + qc == 700)) &&
     ((!sv14 || sv68 || sv5) && (sv47 || !sv36 || sv46) &&
     (!sv68 || !sv33 || sv29) && (sv72 || !sv33 || !sv29) &&
     (sv54 || sv55 || !sv45) && (!sv2 || sv39 || sv55) &&
     (sv31 || sv73 || !sv63) && (!sv43 || sv44 || !sv29) &&
     (sv4 || sv48 || !sv0) && (sv31 || sv18 || sv51) &&
     (!sv72 || sv22 || sv17) && (!sv15 || sv8 || sv47) &&
     (sv41 || !sv33 || !sv37) && (!sv22 || sv33 || sv21) &&
     (!sv44 || sv55 || !sv59) && (sv57 || sv55 || !sv67) &&
     (sv73 || !sv0 || !sv29) && (!sv47 || sv46 || !sv45) &&
     (!sv50 || !sv62 || !sv70) && (!sv15 || !sv8 || sv54) &&
     (sv34 || sv66 || sv8) && (!sv69 || sv18 || !sv11) &&
     (sv1 || !sv35 || sv62) && (!sv68 || sv57 || sv29) &&
     (sv58 || !sv37 || !sv16) && (sv61 || !sv53 || sv36) &&
     (sv25 || sv56 || !sv0) && (!sv29 || !sv12 || !sv36) &&
     (sv35 || sv8 || !sv69) && (sv72 || !sv52 || sv24) &&
     (!sv42 || sv21 || sv23) && (sv29 || sv49 || sv54) &&
     (sv14 || sv21 || !sv22) && (!sv8 || !sv3 || sv25) &&
     (!sv21 || !sv24 || sv69) && (!sv31 || !sv71 || sv14) &&
     (!sv39 || sv13 || sv66) && (sv47 || !sv8 || !sv5) &&
     (!sv31 || !sv6 || !sv48) && (!sv58 || sv64 || !sv52) &&
     (sv8 || sv0 || !sv28) && (!sv49 || sv38 || !sv23) &&
     (!sv16 || !sv9 || sv28) && (sv44 || sv37 || !sv10) &&
     (!sv15 || !sv7 || sv6) && (sv62 || !sv27 || sv66) &&
     (!sv27 || !sv13 || sv15) && (!sv22 || sv67 || !sv27) &&
     (sv36 || sv1 || sv30) && (!sv32 || sv23 || sv69) &&
     (!sv43 || sv28 || !sv48) && (!sv74 || !sv51 || sv70) &&
     (sv17 || !sv36 || sv67) && (!sv26 || sv23 || sv55) &&
     (!sv48 || sv29 || !sv53) && (sv29 || !sv31 || !sv10) &&
     (!sv66 || !sv52 || !sv70) && (!sv23 || sv21 || sv57) &&
     (!sv63 || sv39 || !sv44) && (sv13 || !sv58 || sv32) &&
     (!sv0 || sv17 || !sv47) && (!sv7 || !sv12 || !sv11) &&
     (!sv74 || !sv30 || sv71) && (sv67 || !sv47 || !sv73) &&
     (!sv72 || sv31 || !sv62) && (!sv26 || sv56 || sv58) &&
     (sv73 || sv43 || !sv46) && (sv70 || !sv49 || sv66) &&
     (!sv47 || !sv37 || !sv59) && (sv5 || sv37 || sv10) &&
     (sv31 || sv74 || !sv30) && (!sv40 || sv1 || !sv10) &&
     (sv4 || sv51 || !sv17) && (!sv36 || !sv24 || !sv11) &&
     (sv38 || !sv65 || sv7) && (sv27 || sv51 || sv61) &&
     (!sv72 || sv51 || !sv14) && (!sv71 || sv39 || !sv43) &&
     (!sv59 || !sv14 || sv51) && (sv1 || !sv22 || !sv28) &&
     (!sv30 || !sv29 || sv24) && (!sv28 || sv24 || !sv50) &&
     (!sv29 || !sv26 || !sv13) && (sv23 || !sv44 || !sv19) &&
     (sv61 || sv65 || sv12) && (sv71 || !sv73 || !sv13) &&
     (!sv27 || sv64 || sv23) && (sv8 || sv50 || sv1) &&
     (!sv56 || sv17 || sv60) && (sv71 || !sv70 || !sv44) &&
     (sv36 || sv6 || sv42) && (sv20 || sv16 || !sv65) &&
     (sv50 || !sv12 || sv24) && (!sv50 || sv73 || !sv66) &&
     (sv64 || !sv70 || sv44) && (sv16 || sv1 || sv11) &&
     (sv53 || sv41 || !sv50) && (!sv67 || sv42 || sv33) &&
     (!sv1 || !sv66 || sv55) && (sv23 || sv5 || sv50) &&
     (sv44 || !sv72 || sv70) && (!sv54 || sv1 || !sv42) &&
     (sv20 || sv56 || !sv48) && (sv61 || sv0 || sv47) &&
     (!sv45 || !sv30 || !sv10) && (!sv46 || sv62 || sv29) &&
     (!sv72 || !sv40 || !sv65) && (sv64 || sv66 || !sv5) &&
     (!sv49 || sv9 || sv26) && (sv10 || sv9 || sv31) &&
     (!sv10 || sv5 || !sv31) && (!sv36 || sv53 || !sv70) &&
     (!sv6 || sv55 || sv28) && (!sv29 || !sv51 || sv1) &&
     (!sv6 || !sv48 || sv43) && (!sv12 || sv35 || sv4) &&
     (!sv38 || !sv28 || sv7) && (!sv74 || sv71 || !sv27) &&
     (!sv47 || !sv26 || sv37) && (sv17 || sv31 || sv53) &&
     (!sv57 || sv44 || !sv54) && (!sv2 || sv51 || sv3) &&
     (sv33 || !sv0 || !sv31) && (!sv70 || sv42 || sv34) &&
     (sv5 || !sv30 || !sv60) && (sv71 || sv56 || sv3) &&
     (sv37 || !sv28 || sv22) && (sv13 || !sv71 || !sv55) &&
     (!sv48 || sv33 || sv60) && (!sv41 || sv49 || !sv36) &&
     (!sv70 || !sv17 || sv47) && (!sv37 || !sv20 || sv43) &&
     (!sv19 || !sv41 || sv49) && (!sv72 || sv12 || !sv40) &&
     (sv8 || sv60 || sv3) && (!sv18 || !sv10 || !sv25) &&
     (sv69 || !sv37 || sv2) && (sv33 || !sv10 || !sv5) &&
     (sv45 || !sv15 || !sv3) && (!sv32 || sv15 || sv57) &&
     (!sv38 || sv34 || sv1) && (!sv52 || sv48 || sv70) &&
     (!sv69 || sv23 || sv58) && (!sv50 || sv15 || !sv65) &&
     (sv43 || !sv67 || sv65) && (!sv68 || sv73 || sv26) &&
     (sv56 || !sv64 || sv29) && (sv22 || !sv50 || sv34) &&
     (!sv3 || sv53 || sv47) && (!sv11 || !sv46 || sv68) &&
     (sv3 || !sv48 || !sv32) && (sv22 || sv14 || !sv4) &&
     (sv47 || sv72 || !sv38) && (sv56 || sv44 || !sv14) &&
     (!sv30 || !sv56 || sv11) && (sv15 || !sv16 || !sv24) &&
     (sv67 || !sv4 || sv66) && (!sv72 || sv6 || !sv54) &&
     (sv68 || sv70 || !sv0) && (!sv34 || !sv26 || !sv5) &&
     (sv59 || !sv44 || !sv43) && (sv67 || sv63 || sv40) &&
     (!sv22 || sv9 || !sv10) && (!sv30 || sv62 || sv46) &&
     (sv52 || sv16 || !sv36) && (sv13 || !sv15 || sv8) &&
     (sv6 || sv9 || sv70) && (sv6 || !sv55 || sv51) && (!sv54 || sv47 || sv9) &&
     (!sv43 || sv2 || sv61) && (!sv40 || !sv28 || !sv67) &&
     (!sv35 || !sv33 || sv41) && (!sv41 || !sv53 || sv52) &&
     (!sv20 || sv12 || !sv51) && (sv14 || !sv10 || sv61) &&
     (sv4 || !sv64 || !sv43) && (sv53 || !sv46 || !sv25) &&
     (sv59 || sv38 || !sv48) && (sv33 || sv41 || !sv4) &&
     (!sv3 || !sv69 || !sv10) && (!sv29 || sv22 || !sv13) &&
     (sv40 || !sv2 || sv51) && (!sv33 || !sv51 || sv58) &&
     (!sv65 || !sv69 || sv66) && (sv20 || sv72 || !sv54) &&
     (sv64 || sv32 || !sv16) && (!sv74 || sv15 || sv70) &&
     (!sv3 || !sv64 || sv5) && (sv51 || sv71 || !sv34) &&
     (sv40 || sv27 || !sv57) && (!sv43 || sv3 || !sv58) &&
     (sv60 || sv8 || sv13) && (sv39 || sv0 || !sv53) &&
     (sv18 || !sv48 || !sv12) && (sv31 || !sv6 || sv14) &&
     (!sv26 || sv54 || sv61) && (sv63 || !sv73 || sv18) &&
     (sv31 || sv1 || sv69) && (sv38 || !sv42 || sv13) &&
     (sv4 || sv50 || !sv72) && (sv36 || sv57 || !sv61) &&
     (sv72 || !sv43 || sv36) && (!sv25 || sv5 || sv6) &&
     (sv69 || sv68 || !sv16) && (!sv7 || !sv41 || !sv55) &&
     (!sv7 || !sv68 || !sv18) && (sv69 || !sv64 || sv32) &&
     (sv59 || sv69 || !sv67) && (sv17 || !sv10 || sv56) &&
     (sv67 || sv51 || sv14) && (!sv49 || !sv15 || sv13) &&
     (sv5 || sv62 || !sv23) && (sv35 || !sv58 || !sv43) &&
     (!sv12 || sv30 || sv23) && (sv40 || !sv26 || sv36) &&
     (sv36 || sv70 || sv65) && (sv8 || !sv12 || !sv46) &&
     (!sv59 || sv12 || sv3) && (!sv64 || sv15 || !sv6) &&
     (!sv62 || sv34 || sv31) && (!sv26 || !sv12 || !sv45) &&
     (sv50 || sv7 || sv22) && (!sv52 || sv42 || sv11) &&
     (!sv58 || sv46 || !sv72) && (!sv36 || !sv20 || !sv64) &&
     (!sv32 || !sv46 || !sv10) && (!sv66 || sv23 || !sv61) &&
     (!sv74 || !sv70 || !sv10) && (sv37 || !sv18 || sv14) &&
     (sv33 || sv57 || !sv15) && (!sv38 || !sv52 || !sv49) &&
     (!sv40 || !sv26 || !sv51) && (!sv3 || sv29 || sv66) &&
     (sv33 || !sv40 || sv27) && (sv58 || sv49 || sv14) &&
     (sv42 || sv28 || !sv43) && (!sv24 || sv4 || !sv10) &&
     (!sv66 || sv35 || sv46) && (sv3 || !sv39 || !sv5) &&
     (sv46 || !sv35 || sv72) && (!sv51 || !sv13 || !sv32) &&
     (!sv2 || sv62 || !sv0) && (!sv51 || !sv40 || sv18) &&
     (!sv66 || !sv16 || !sv60) && (!sv20 || !sv53 || sv28) &&
     (sv16 || sv62 || !sv29) && (!sv7 || !sv35 || !sv50) &&
     (!sv58 || sv55 || !sv8) && (sv12 || !sv18 || !sv7) &&
     (sv5 || !sv42 || !sv18) && (!sv35 || !sv36 || !sv25) &&
     (sv1 || !sv62 || !sv70) && (sv66 || !sv62 || sv22) &&
     (!sv30 || sv19 || !sv23) && (!sv66 || sv60 || sv7) &&
     (!sv63 || sv5 || !sv40) && (sv54 || sv19 || !sv1) &&
     (!sv53 || sv63 || sv22) && (!sv35 || !sv34 || sv21) &&
     (!sv34 || sv47 || sv39) && (!sv20 || !sv1 || !sv36) &&
     (sv44 || !sv4 || !sv22) && (!sv49 || sv28 || !sv27) &&
     (sv56 || !sv8 || sv46) && (sv29 || !sv43 || sv39) &&
     (!sv68 || sv60 || !sv57) && (!sv25 || sv10 || !sv17) &&
     (sv19 || sv65 || !sv18) && (sv68 || sv19 || !sv28) &&
     (sv3 || sv35 || sv39) && (!sv16 || !sv42 || sv35) &&
     (!sv53 || sv73 || !sv7) && (sv62 || sv48 || !sv70) &&
     (!sv40 || !sv41 || !sv61) && (!sv48 || !sv10 || sv15) &&
     (!sv46 || sv73 || sv42) && (sv72 || !sv0 || !sv16) &&
     (sv29 || sv74 || !sv46) && (!sv21 || !sv8 || !sv72) &&
     (sv20 || !sv19 || !sv33) && (sv68 || !sv32 || sv74) &&
     (sv40 || !sv1 || !sv17) && (!sv23 || sv42 || sv62) &&
     (sv47 || sv9 || sv4) && (sv17 || !sv19 || sv69) &&
     (!sv9 || sv54 || sv16) && (sv7 || !sv28 || !sv5) &&
     (!sv40 || sv66 || sv16) && (!sv51 || sv12 || !sv7) &&
     (!sv51 || !sv44 || !sv36) && (sv19 || sv51 || sv40) &&
     (!sv60 || !sv59 || sv68) && (sv9 || !sv48 || sv15) &&
     (sv29 || !sv56 || !sv69) && (!sv12 || sv41 || !sv36) &&
     (!sv43 || !sv55 || !sv21) && (!sv32 || sv35 || sv52) &&
     (!sv12 || !sv23 || sv60) && (!sv62 || sv15 || !sv58) &&
     (sv21 || !sv17 || !sv33) && (sv16 || !sv52 || !sv60) &&
     (!sv32 || sv53 || sv39) && (sv2 || !sv40 || sv18) &&
     (sv38 || sv70 || !sv15) && (sv45 || !sv12 || sv19) &&
     (sv36 || !sv60 || sv38) && (sv66 || !sv55 || !sv8) &&
     (sv22 || sv63 || sv23) && (!sv11 || !sv8 || sv42) &&
     (sv9 || sv45 || sv64) && (!sv37 || !sv10 || !sv1) &&
     (sv44 || sv13 || sv64) && (!sv24 || sv19 || !sv3) &&
     (sv27 || sv5 || sv53) && (!sv52 || sv11 || !sv71) &&
     (sv56 || sv48 || !sv44) && (!sv33 || sv74 || sv37) &&
     (!sv49 || !sv18 || sv33) && (sv25 || sv71 || !sv46) &&
     (!sv54 || !sv28 || sv4) && (sv37 || sv2 || !sv63) &&
     (!sv57 || !sv5 || !sv43) && (sv65 || !sv42 || !sv20) &&
     (!sv23 || !sv26 || sv74) && (sv23 || sv21 || sv45))) {
            const char *safe_query = "SELECT id, email FROM users WHERE name = ?";
            return db_exec_param(safe_query, sanitized_username);
    } else {
            const char *safe_query = "SELECT id, email FROM users WHERE name = ?";
            return db_exec_param(safe_query, sanitized_username);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <username>\n", argv[0]);
        return 2;
    }
    return lookup_user(argv[1]);
}
