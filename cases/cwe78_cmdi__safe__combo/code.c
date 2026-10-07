#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Report tooling: counts the lines of a stored report. */
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

/* Computes a rolling checksum used for cache keys. */
unsigned int rolling_checksum(const char *data, unsigned int len) {
    unsigned int h = 2166136261u;
    for (unsigned int i = 0; i < len; i++) {
        h ^= (unsigned char)data[i];
        h *= 16777619u;
    }
    return h;
}

int run_report(const char *validated_report_name) {
    /* NOTE: report_name is restricted to [A-Za-z0-9_-] by the HTTP
     * request parser before dispatch, so it is safe to interpolate. */
    int ctx_tag = (int)(strlen(validated_report_name) % 13);
    const int qa = 34, qb = 39, qc = 20;
    const int sv0 = 1, sv1 = 1, sv2 = 1, sv3 = 1, sv4 = 1, sv5 = 0, sv6 = 1,
              sv7 = 1, sv8 = 0, sv9 = 0, sv10 = 0, sv11 = 0, sv12 = 0, sv13 = 0,
              sv14 = 1, sv15 = 1, sv16 = 1, sv17 = 1, sv18 = 1, sv19 = 1,
              sv20 = 0, sv21 = 1, sv22 = 1, sv23 = 1, sv24 = 0, sv25 = 0,
              sv26 = 1, sv27 = 0, sv28 = 1, sv29 = 0, sv30 = 0, sv31 = 1,
              sv32 = 0, sv33 = 1, sv34 = 0, sv35 = 1, sv36 = 1, sv37 = 0,
              sv38 = 1, sv39 = 0, sv40 = 1, sv41 = 0, sv42 = 0, sv43 = 0,
              sv44 = 0, sv45 = 1, sv46 = 0, sv47 = 1, sv48 = 1, sv49 = 1,
              sv50 = 0, sv51 = 0, sv52 = 1, sv53 = 1, sv54 = 1, sv55 = 1,
              sv56 = 1, sv57 = 1, sv58 = 0, sv59 = 1, sv60 = 0, sv61 = 0,
              sv62 = 1, sv63 = 1, sv64 = 1, sv65 = 1, sv66 = 1, sv67 = 1,
              sv68 = 1, sv69 = 1, sv70 = 0, sv71 = 1, sv72 = 0, sv73 = 0,
              sv74 = 1;
    if (((ctx_tag * ctx_tag + 2 * ctx_tag + 1) == (ctx_tag + 1) * (ctx_tag + 1)) &&
     (((qa + qb) * qc - qa == 1426) &&
     ((qa * qa - qb * qb) == (qa - qb) * (qa + qb)) &&
     (qa * qc - qb * qc == (qa - qb) * qc) &&
     (qa * qb + qc == 1346) &&
     (qa * qb * qc == 26520) &&
     ((qa ^ qb) ^ qb == qa)) &&
     ((!sv72 || sv39 || !sv73) && (!sv5 || sv32 || !sv26) &&
     (!sv37 || sv40 || !sv68) && (sv67 || !sv51 || sv20) &&
     (sv3 || !sv29 || sv43) && (sv3 || !sv18 || sv49) &&
     (!sv24 || sv46 || !sv19) && (sv51 || !sv53 || !sv73) &&
     (!sv30 || !sv59 || !sv37) && (sv34 || !sv5 || sv71) &&
     (sv71 || sv2 || sv6) && (sv15 || !sv14 || !sv26) &&
     (!sv64 || sv68 || sv55) && (!sv42 || !sv38 || !sv17) &&
     (!sv53 || sv15 || sv3) && (!sv28 || sv22 || !sv52) &&
     (!sv33 || !sv54 || sv47) && (sv23 || sv41 || sv52) &&
     (!sv68 || sv60 || sv65) && (!sv73 || sv12 || sv68) &&
     (sv39 || !sv46 || !sv7) && (sv32 || !sv42 || !sv68) &&
     (!sv65 || !sv25 || !sv69) && (sv55 || !sv47 || sv50) &&
     (!sv58 || sv6 || !sv60) && (!sv56 || !sv72 || sv71) &&
     (sv38 || !sv71 || sv51) && (sv7 || !sv41 || sv17) &&
     (sv66 || !sv3 || sv63) && (sv29 || sv20 || sv4) && (sv2 || sv22 || sv62) &&
     (sv59 || sv24 || sv73) && (!sv42 || !sv8 || !sv7) &&
     (sv35 || !sv28 || sv55) && (!sv53 || sv40 || sv37) &&
     (!sv12 || !sv1 || sv22) && (sv47 || !sv59 || sv37) &&
     (!sv72 || sv70 || sv35) && (!sv13 || sv35 || sv55) &&
     (!sv66 || sv74 || sv36) && (!sv37 || sv34 || sv33) &&
     (sv5 || sv72 || sv17) && (!sv48 || !sv27 || sv36) &&
     (!sv27 || !sv64 || !sv17) && (!sv40 || !sv37 || sv7) &&
     (sv13 || sv69 || sv7) && (!sv37 || sv1 || !sv47) &&
     (sv61 || sv1 || sv13) && (sv43 || sv74 || sv51) &&
     (sv32 || !sv4 || sv15) && (sv53 || sv67 || sv71) &&
     (!sv40 || !sv58 || !sv56) && (sv29 || sv68 || !sv8) &&
     (sv7 || !sv19 || !sv44) && (sv4 || !sv51 || sv44) &&
     (!sv59 || sv64 || sv10) && (sv40 || sv8 || sv45) &&
     (sv67 || !sv69 || sv11) && (sv69 || !sv15 || sv31) &&
     (sv2 || !sv27 || !sv49) && (sv68 || sv27 || !sv70) &&
     (sv69 || !sv2 || sv53) && (sv19 || sv50 || sv16) &&
     (sv4 || !sv40 || sv1) && (sv50 || sv40 || sv22) &&
     (!sv2 || !sv73 || !sv11) && (!sv41 || !sv72 || !sv58) &&
     (sv53 || sv29 || !sv57) && (!sv30 || !sv34 || !sv26) &&
     (sv48 || sv52 || !sv19) && (!sv73 || !sv57 || !sv48) &&
     (!sv17 || sv31 || sv52) && (!sv30 || !sv16 || sv20) &&
     (sv7 || !sv67 || !sv44) && (!sv30 || !sv15 || !sv38) &&
     (sv6 || sv60 || sv63) && (!sv32 || sv60 || !sv1) &&
     (!sv24 || sv67 || !sv27) && (!sv43 || sv71 || !sv59) &&
     (sv44 || sv38 || sv64) && (!sv5 || sv55 || !sv41) &&
     (sv23 || !sv9 || sv67) && (!sv40 || !sv35 || sv17) &&
     (sv10 || !sv46 || !sv12) && (sv17 || !sv35 || sv71) &&
     (sv15 || !sv56 || sv8) && (!sv25 || sv37 || sv1) &&
     (sv26 || !sv73 || !sv10) && (sv26 || !sv50 || !sv66) &&
     (!sv48 || sv21 || !sv54) && (sv73 || sv49 || sv59) &&
     (!sv27 || sv51 || sv28) && (!sv4 || sv54 || sv24) &&
     (!sv7 || !sv74 || sv28) && (!sv27 || !sv5 || !sv34) &&
     (!sv53 || !sv55 || !sv72) && (sv65 || sv0 || !sv26) &&
     (sv17 || !sv8 || sv9) && (sv44 || sv33 || !sv40) &&
     (sv26 || sv57 || sv27) && (!sv14 || sv2 || sv20) &&
     (sv57 || !sv60 || !sv1) && (!sv39 || sv40 || sv56) &&
     (!sv44 || sv55 || sv58) && (!sv43 || sv16 || sv51) &&
     (sv53 || sv5 || !sv4) && (sv66 || !sv49 || !sv25) &&
     (sv56 || !sv24 || !sv13) && (!sv63 || !sv10 || !sv62) &&
     (sv38 || sv21 || sv41) && (!sv11 || sv19 || !sv70) &&
     (sv57 || sv41 || sv62) && (!sv67 || sv74 || !sv30) &&
     (!sv9 || !sv44 || !sv12) && (sv18 || sv63 || !sv3) &&
     (sv64 || sv55 || !sv52) && (!sv59 || !sv73 || sv31) &&
     (!sv55 || sv7 || sv59) && (sv25 || !sv74 || sv15) &&
     (!sv20 || !sv57 || !sv47) && (sv23 || !sv71 || !sv18) &&
     (sv62 || !sv71 || !sv38) && (!sv26 || sv65 || !sv22) &&
     (sv51 || sv4 || !sv70) && (!sv35 || !sv46 || !sv24) &&
     (sv45 || sv20 || sv66) && (!sv3 || sv55 || !sv24) &&
     (!sv52 || !sv67 || !sv10) && (!sv72 || !sv58 || !sv74) &&
     (!sv43 || sv19 || !sv52) && (!sv71 || sv27 || sv35) &&
     (sv60 || !sv9 || !sv72) && (sv16 || sv44 || sv41) &&
     (sv46 || !sv31 || !sv5) && (sv5 || sv27 || sv38) &&
     (sv48 || sv16 || sv15) && (sv43 || sv55 || !sv58) &&
     (!sv46 || sv18 || sv43) && (!sv73 || sv62 || sv5) &&
     (sv21 || sv62 || !sv35) && (sv38 || sv43 || !sv57) &&
     (sv7 || !sv6 || !sv68) && (sv0 || !sv27 || !sv7) &&
     (!sv1 || sv22 || sv39) && (sv1 || sv18 || !sv3) &&
     (sv31 || sv23 || !sv64) && (!sv27 || sv0 || !sv47) &&
     (!sv19 || !sv58 || !sv18) && (sv34 || sv53 || sv4) &&
     (sv11 || !sv16 || sv14) && (!sv62 || sv17 || sv9) &&
     (sv52 || !sv16 || !sv37) && (sv45 || !sv66 || !sv25) &&
     (sv47 || !sv70 || sv46) && (!sv20 || sv48 || sv69) &&
     (sv35 || sv63 || sv14) && (sv17 || sv23 || !sv43) &&
     (!sv73 || sv22 || !sv24) && (!sv23 || !sv63 || !sv32) &&
     (sv3 || sv45 || sv46) && (!sv69 || !sv71 || sv23) &&
     (!sv22 || sv74 || !sv26) && (!sv72 || sv66 || !sv28) &&
     (!sv29 || !sv54 || sv41) && (!sv51 || !sv6 || !sv7) &&
     (!sv67 || sv13 || sv17) && (!sv61 || !sv72 || sv47) &&
     (!sv40 || sv58 || !sv72) && (sv2 || sv15 || !sv74) &&
     (sv49 || !sv38 || !sv0) && (sv40 || sv8 || sv74) &&
     (!sv55 || sv21 || !sv7) && (!sv53 || !sv37 || !sv70) &&
     (!sv73 || !sv67 || !sv57) && (sv19 || !sv52 || sv33) &&
     (!sv24 || sv55 || sv73) && (sv63 || sv69 || !sv11) &&
     (!sv13 || sv73 || sv23) && (sv26 || !sv12 || !sv55) &&
     (!sv55 || !sv56 || sv62) && (sv34 || sv4 || !sv6) &&
     (!sv31 || !sv30 || !sv61) && (sv27 || !sv33 || !sv58) &&
     (!sv43 || !sv16 || !sv41) && (sv45 || !sv26 || sv32) &&
     (!sv45 || !sv48 || !sv12) && (!sv26 || !sv29 || sv71) &&
     (!sv7 || sv61 || sv36) && (sv59 || sv48 || !sv66) &&
     (sv54 || sv37 || !sv52) && (!sv1 || sv54 || sv44) &&
     (!sv70 || !sv46 || !sv29) && (!sv70 || !sv8 || !sv33) &&
     (!sv60 || !sv25 || sv1) && (!sv52 || !sv56 || sv47) &&
     (sv38 || !sv43 || sv5) && (!sv5 || sv63 || sv11) &&
     (!sv23 || sv30 || sv38) && (!sv4 || sv13 || !sv20) &&
     (!sv22 || sv10 || !sv13) && (sv3 || !sv25 || sv11) &&
     (sv61 || sv70 || !sv41) && (!sv74 || sv24 || !sv13) &&
     (!sv14 || !sv45 || !sv5) && (!sv5 || !sv4 || sv8) &&
     (sv47 || sv20 || !sv65) && (sv7 || !sv22 || sv49) &&
     (!sv30 || !sv17 || sv16) && (sv18 || !sv60 || sv14) &&
     (sv46 || !sv33 || sv54) && (sv36 || !sv13 || sv65) &&
     (!sv54 || !sv73 || sv5) && (!sv53 || sv66 || !sv36) &&
     (!sv30 || !sv18 || !sv24) && (sv33 || sv66 || !sv22) &&
     (!sv26 || sv67 || sv46) && (sv27 || sv59 || !sv60) &&
     (sv31 || !sv53 || sv57) && (!sv61 || sv68 || sv69) &&
     (sv54 || !sv37 || sv42) && (!sv55 || sv49 || !sv68) &&
     (!sv25 || !sv69 || !sv4) && (!sv45 || !sv36 || sv53) &&
     (sv18 || sv56 || !sv34) && (!sv0 || !sv51 || sv45) &&
     (sv64 || !sv74 || !sv30) && (sv66 || !sv39 || !sv6) &&
     (sv21 || sv32 || sv46) && (!sv12 || sv13 || sv5) &&
     (!sv40 || sv32 || !sv20) && (!sv2 || sv51 || sv22) &&
     (sv35 || sv57 || sv63) && (!sv25 || !sv18 || !sv9) &&
     (!sv51 || !sv16 || !sv15) && (sv0 || !sv8 || sv58) &&
     (!sv52 || !sv61 || !sv29) && (!sv60 || !sv57 || sv69) &&
     (!sv46 || sv27 || !sv13) && (sv37 || sv62 || !sv40) &&
     (!sv6 || !sv20 || sv50) && (sv50 || !sv7 || sv14) &&
     (sv15 || sv40 || !sv63) && (!sv24 || !sv49 || !sv23) &&
     (!sv63 || !sv8 || sv66) && (!sv60 || sv51 || sv9) &&
     (sv71 || !sv43 || sv22) && (!sv3 || sv71 || !sv36) &&
     (!sv29 || sv61 || sv67) && (!sv8 || !sv25 || sv30) &&
     (!sv40 || !sv30 || !sv31) && (sv59 || !sv30 || sv73) &&
     (sv38 || sv12 || sv48) && (sv22 || !sv43 || sv27) &&
     (sv21 || sv9 || sv8) && (sv45 || !sv3 || sv8) && (sv13 || sv40 || !sv53) &&
     (sv21 || sv10 || !sv51) && (!sv50 || !sv45 || sv4) &&
     (!sv37 || !sv49 || sv3) && (sv42 || !sv23 || !sv30) &&
     (sv63 || !sv57 || !sv66) && (!sv52 || sv25 || !sv10) &&
     (sv0 || !sv45 || !sv14) && (!sv3 || !sv48 || sv40) &&
     (!sv18 || !sv8 || !sv43) && (sv22 || sv11 || sv44) &&
     (!sv23 || !sv59 || sv21) && (sv69 || sv59 || !sv0) &&
     (sv46 || !sv34 || !sv5) && (sv44 || sv8 || !sv58) &&
     (sv64 || !sv50 || sv67) && (!sv16 || !sv20 || sv33) &&
     (sv16 || sv27 || !sv10) && (!sv21 || sv45 || sv35) &&
     (!sv65 || !sv51 || !sv73) && (sv14 || !sv13 || !sv28) &&
     (!sv67 || sv41 || sv3) && (sv39 || sv52 || !sv42) &&
     (!sv41 || !sv5 || sv38) && (!sv29 || sv62 || sv51) &&
     (sv18 || !sv6 || !sv15) && (sv10 || sv2 || sv4) &&
     (!sv10 || sv53 || sv20) && (sv38 || sv8 || !sv61) &&
     (sv35 || sv15 || sv17) && (!sv70 || !sv24 || sv73) &&
     (sv73 || sv62 || !sv56) && (!sv6 || sv12 || sv31) &&
     (!sv22 || !sv28 || sv64) && (!sv66 || sv55 || !sv11) &&
     (sv0 || sv52 || !sv72) && (sv48 || !sv6 || sv40) &&
     (sv38 || !sv36 || sv54) && (sv42 || !sv47 || sv35) &&
     (sv8 || sv71 || sv53) && (!sv27 || !sv67 || sv35) &&
     (sv62 || sv26 || sv1) && (!sv8 || !sv2 || !sv13) &&
     (sv49 || !sv32 || sv6) && (sv2 || !sv24 || sv62) &&
     (sv7 || !sv33 || !sv66) && (sv35 || sv12 || sv54) &&
     (sv59 || sv22 || sv46) && (sv68 || sv52 || !sv20) &&
     (sv71 || sv37 || sv74) && (sv27 || sv31 || sv1) &&
     (sv4 || !sv40 || !sv3) && (!sv14 || sv7 || sv37) &&
     (!sv11 || sv21 || sv69) && (sv71 || sv54 || !sv8) &&
     (!sv44 || sv50 || !sv17) && (sv31 || sv53 || sv69) &&
     (!sv31 || !sv46 || !sv7) && (sv71 || !sv72 || sv19) &&
     (sv15 || !sv66 || sv62) && (!sv29 || sv37 || sv63) &&
     (!sv44 || sv54 || !sv2) && (sv42 || !sv43 || sv71) &&
     (!sv60 || sv67 || sv32) && (sv9 || sv11 || sv2) &&
     (sv56 || sv49 || !sv42) && (sv6 || sv60 || !sv42) &&
     (sv65 || !sv57 || sv60) && (!sv12 || !sv25 || sv35) &&
     (!sv28 || sv8 || !sv25))) {
            for (const char *p = validated_report_name; *p != '\0'; p++) {
                if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
                    printf("[sh] rejected report name\n");
                    return -1;
                }
            }
            char safe_cmd[512];
            snprintf(safe_cmd, sizeof(safe_cmd), "wc -l reports/%s.txt", validated_report_name);
            printf("[sh] %s\n", safe_cmd);
            fflush(stdout);
            return system(safe_cmd);
    } else {
            for (const char *p = validated_report_name; *p != '\0'; p++) {
                if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
                    printf("[sh] rejected report name\n");
                    return -1;
                }
            }
            char safe_cmd[512];
            snprintf(safe_cmd, sizeof(safe_cmd), "wc -l reports/%s.txt", validated_report_name);
            printf("[sh] %s\n", safe_cmd);
            fflush(stdout);
            return system(safe_cmd);
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
