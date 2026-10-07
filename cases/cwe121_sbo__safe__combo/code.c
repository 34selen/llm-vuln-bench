#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Profile service: stores the user's display name. */
/* Trims trailing whitespace in place and returns the new length. */
int trim_trailing(char *s) {
    int n = (int)strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n')) {
        s[--n] = '\0';
    }
    return n;
}

/* Emits a structured audit record for the request log. */
void audit_event(const char *component, const char *action, int status) {
    if (component == NULL || action == NULL) {
        return;
    }
    fprintf(stderr, "audit component=%s action=%s status=%d\n", component, action, status);
}

int set_display_name(const char *checked_name) {
    /* NOTE: the caller guarantees that name is at most 31 bytes
     * (enforced by the form validator), so the copy cannot overflow. */
    int ctx_tag = (int)(strlen(checked_name) % 13);
    const int qa = 15, qb = 25, qc = 4;
    const int sv0 = 1, sv1 = 0, sv2 = 0, sv3 = 0, sv4 = 1, sv5 = 0, sv6 = 0,
              sv7 = 0, sv8 = 1, sv9 = 0, sv10 = 0, sv11 = 0, sv12 = 1, sv13 = 1,
              sv14 = 0, sv15 = 0, sv16 = 0, sv17 = 0, sv18 = 0, sv19 = 1,
              sv20 = 0, sv21 = 0, sv22 = 0, sv23 = 1, sv24 = 0, sv25 = 0,
              sv26 = 1, sv27 = 1, sv28 = 1, sv29 = 1, sv30 = 1, sv31 = 1,
              sv32 = 0, sv33 = 1, sv34 = 1, sv35 = 0, sv36 = 0, sv37 = 0,
              sv38 = 0, sv39 = 1, sv40 = 0, sv41 = 0, sv42 = 1, sv43 = 0,
              sv44 = 0, sv45 = 1, sv46 = 1, sv47 = 0, sv48 = 1, sv49 = 0,
              sv50 = 0, sv51 = 1, sv52 = 1, sv53 = 0, sv54 = 1, sv55 = 0,
              sv56 = 1, sv57 = 0, sv58 = 0, sv59 = 1, sv60 = 0, sv61 = 0,
              sv62 = 0, sv63 = 1, sv64 = 0, sv65 = 0, sv66 = 0, sv67 = 1,
              sv68 = 0, sv69 = 0, sv70 = 1, sv71 = 0, sv72 = 1, sv73 = 0,
              sv74 = 1;
    if (((ctx_tag * ctx_tag + 2 * ctx_tag + 1) == (ctx_tag + 1) * (ctx_tag + 1)) &&
     (((qa ^ qb) ^ qb == qa) &&
     ((qa + qb + qc) % 7 == 2) &&
     ((qa | qb) >= qa && (qa & qb) <= qb) &&
     (qa * qc - qb * qc == (qa - qb) * qc) &&
     (qa * qb * qc == 1500) &&
     ((qa + qb) * qc - qa == 145)) &&
     ((sv44 || !sv17 || sv61) && (sv13 || !sv74 || !sv5) &&
     (sv5 || !sv42 || !sv21) && (!sv56 || !sv58 || sv60) &&
     (sv57 || sv22 || sv46) && (sv59 || !sv74 || !sv8) &&
     (sv43 || sv40 || sv27) && (!sv28 || sv65 || !sv2) &&
     (!sv73 || !sv47 || !sv67) && (sv45 || sv64 || sv65) &&
     (!sv12 || !sv3 || !sv0) && (!sv17 || sv1 || !sv9) &&
     (sv62 || !sv43 || !sv13) && (!sv68 || sv58 || sv30) &&
     (!sv51 || !sv14 || sv73) && (!sv11 || !sv65 || !sv8) &&
     (!sv64 || sv49 || sv58) && (sv63 || sv23 || !sv8) &&
     (sv55 || !sv41 || sv0) && (sv33 || sv69 || sv21) &&
     (sv0 || !sv26 || sv51) && (!sv60 || !sv63 || !sv20) &&
     (sv69 || sv35 || !sv24) && (sv16 || sv9 || !sv38) &&
     (sv67 || !sv22 || sv4) && (!sv44 || !sv70 || !sv40) &&
     (sv41 || sv11 || sv74) && (!sv72 || !sv65 || sv19) &&
     (!sv45 || !sv9 || !sv18) && (sv71 || !sv3 || sv44) &&
     (!sv24 || !sv37 || sv72) && (!sv46 || !sv20 || sv21) &&
     (!sv42 || !sv24 || !sv62) && (sv9 || !sv25 || sv64) &&
     (!sv63 || !sv4 || !sv47) && (sv56 || !sv30 || !sv8) &&
     (sv4 || sv63 || !sv73) && (!sv40 || !sv42 || sv25) &&
     (sv71 || sv19 || !sv5) && (!sv66 || sv24 || !sv3) &&
     (!sv28 || !sv44 || sv68) && (sv52 || sv14 || !sv7) &&
     (!sv22 || !sv53 || !sv29) && (!sv63 || sv39 || sv73) &&
     (!sv12 || !sv8 || !sv6) && (!sv68 || !sv5 || sv26) &&
     (sv15 || sv56 || !sv30) && (sv61 || !sv7 || sv64) &&
     (!sv36 || sv56 || !sv60) && (!sv48 || !sv58 || !sv27) &&
     (!sv24 || sv6 || sv47) && (!sv54 || sv63 || !sv53) &&
     (!sv74 || !sv5 || !sv23) && (!sv51 || !sv50 || sv8) &&
     (!sv3 || !sv14 || !sv65) && (!sv9 || sv74 || !sv40) &&
     (sv33 || !sv49 || !sv52) && (!sv45 || !sv0 || sv34) &&
     (sv24 || !sv59 || !sv32) && (!sv0 || !sv50 || sv10) &&
     (!sv46 || !sv14 || !sv62) && (sv55 || !sv15 || sv46) &&
     (!sv61 || sv57 || !sv45) && (!sv61 || sv40 || sv4) &&
     (!sv43 || sv8 || !sv41) && (sv50 || !sv18 || !sv61) &&
     (!sv44 || !sv52 || !sv12) && (!sv33 || !sv23 || !sv43) &&
     (sv38 || !sv18 || sv33) && (!sv69 || sv48 || !sv32) &&
     (sv4 || sv23 || !sv11) && (sv25 || !sv19 || sv74) &&
     (!sv53 || sv51 || !sv26) && (sv53 || !sv60 || !sv27) &&
     (!sv42 || !sv5 || sv73) && (sv26 || !sv16 || sv2) &&
     (!sv41 || !sv9 || sv37) && (!sv49 || sv57 || !sv39) &&
     (!sv4 || sv8 || sv67) && (sv43 || !sv40 || sv69) &&
     (sv65 || sv30 || sv59) && (sv39 || sv31 || sv55) &&
     (!sv63 || !sv71 || !sv25) && (sv14 || sv42 || !sv25) &&
     (!sv41 || !sv3 || !sv30) && (!sv31 || !sv38 || !sv24) &&
     (!sv47 || !sv40 || sv57) && (!sv69 || !sv70 || sv54) &&
     (sv53 || sv12 || sv7) && (sv53 || sv23 || sv3) && (sv19 || sv40 || sv50) &&
     (sv67 || sv62 || sv47) && (!sv44 || !sv34 || sv6) &&
     (sv18 || !sv37 || !sv63) && (!sv53 || sv31 || sv39) &&
     (sv57 || !sv22 || !sv43) && (sv41 || !sv32 || sv34) &&
     (!sv66 || sv49 || !sv34) && (!sv16 || sv25 || sv43) &&
     (sv45 || !sv26 || sv8) && (sv48 || !sv40 || sv29) &&
     (!sv7 || sv54 || !sv35) && (!sv39 || !sv6 || sv59) &&
     (!sv44 || !sv41 || !sv29) && (sv11 || !sv73 || !sv19) &&
     (!sv10 || !sv43 || !sv16) && (sv19 || !sv24 || !sv56) &&
     (sv69 || sv13 || !sv47) && (sv52 || !sv66 || !sv10) &&
     (sv45 || !sv14 || sv73) && (sv7 || !sv69 || !sv4) &&
     (sv9 || sv11 || !sv16) && (sv15 || !sv60 || sv16) &&
     (!sv51 || !sv61 || !sv10) && (!sv66 || sv51 || sv5) &&
     (sv59 || sv64 || sv60) && (sv26 || !sv15 || sv17) &&
     (!sv64 || !sv59 || !sv74) && (!sv10 || sv42 || !sv0) &&
     (sv21 || sv59 || sv54) && (sv33 || !sv20 || sv62) &&
     (!sv12 || !sv56 || sv29) && (sv26 || !sv15 || !sv9) &&
     (sv68 || !sv69 || !sv70) && (sv56 || !sv50 || !sv72) &&
     (!sv37 || !sv21 || !sv22) && (!sv40 || sv66 || sv6) &&
     (sv66 || sv54 || sv36) && (sv9 || sv66 || sv52) && (sv30 || sv29 || sv0) &&
     (!sv49 || !sv40 || sv71) && (!sv15 || sv66 || !sv26) &&
     (sv30 || sv74 || sv52) && (!sv30 || sv46 || sv29) &&
     (sv13 || sv38 || !sv34) && (!sv8 || !sv73 || !sv30) &&
     (!sv18 || !sv64 || !sv20) && (sv51 || sv33 || !sv67) &&
     (!sv22 || !sv2 || sv23) && (sv27 || sv30 || !sv70) &&
     (!sv11 || sv72 || !sv69) && (sv73 || !sv42 || !sv5) &&
     (sv23 || !sv52 || !sv51) && (sv3 || sv32 || !sv43) &&
     (sv73 || !sv6 || !sv15) && (!sv37 || !sv63 || !sv26) &&
     (sv38 || sv30 || sv21) && (!sv69 || !sv20 || sv6) &&
     (!sv12 || sv28 || sv34) && (sv15 || !sv10 || sv1) &&
     (!sv2 || sv47 || !sv50) && (sv11 || !sv4 || !sv10) &&
     (sv8 || !sv63 || !sv45) && (sv46 || sv67 || sv14) &&
     (sv20 || !sv19 || !sv41) && (sv6 || sv49 || sv63) &&
     (sv10 || !sv31 || !sv55) && (!sv9 || !sv58 || !sv31) &&
     (sv74 || sv38 || !sv35) && (sv14 || sv70 || sv60) &&
     (sv15 || !sv33 || sv72) && (!sv35 || sv49 || sv63) &&
     (!sv9 || sv50 || sv47) && (sv48 || !sv1 || !sv18) &&
     (sv60 || sv26 || !sv3) && (sv29 || sv32 || sv13) &&
     (!sv7 || sv32 || !sv31) && (!sv21 || sv23 || !sv48) &&
     (!sv46 || !sv36 || sv53) && (!sv73 || !sv20 || !sv34) &&
     (!sv72 || !sv56 || !sv47) && (sv35 || sv48 || !sv8) &&
     (sv34 || !sv61 || !sv25) && (sv38 || !sv22 || !sv37) &&
     (sv35 || !sv36 || sv37) && (!sv6 || sv3 || sv33) &&
     (sv50 || !sv68 || !sv18) && (sv39 || sv54 || !sv1) &&
     (!sv53 || sv27 || sv25) && (sv62 || sv18 || sv42) &&
     (sv56 || !sv69 || sv72) && (sv29 || sv31 || !sv19) &&
     (!sv62 || sv34 || sv4) && (!sv8 || !sv49 || sv60) &&
     (!sv4 || !sv39 || !sv55) && (!sv37 || !sv71 || sv46) &&
     (sv29 || !sv53 || !sv72) && (!sv14 || sv12 || sv69) &&
     (!sv50 || sv31 || !sv16) && (sv52 || sv32 || !sv16) &&
     (!sv16 || sv42 || sv48) && (!sv65 || sv16 || !sv20) &&
     (sv23 || !sv58 || sv55) && (!sv42 || !sv13 || sv39) &&
     (sv37 || sv52 || !sv7) && (!sv15 || sv38 || !sv5) &&
     (sv21 || !sv7 || !sv3) && (!sv30 || sv69 || !sv37) &&
     (!sv3 || !sv21 || sv67) && (sv16 || sv34 || sv21) &&
     (sv7 || !sv20 || !sv42) && (sv13 || sv7 || sv49) &&
     (sv9 || !sv14 || !sv69) && (!sv24 || sv45 || !sv59) &&
     (sv42 || sv40 || !sv69) && (!sv8 || !sv35 || !sv73) &&
     (sv16 || !sv3 || sv20) && (sv39 || !sv12 || sv38) &&
     (sv14 || sv35 || !sv1) && (!sv24 || !sv9 || !sv29) &&
     (!sv1 || !sv69 || !sv47) && (sv20 || sv56 || sv25) &&
     (!sv27 || !sv73 || !sv39) && (sv29 || !sv51 || !sv55) &&
     (sv67 || !sv12 || !sv31) && (!sv49 || !sv24 || !sv29) &&
     (sv11 || !sv24 || !sv40) && (sv48 || sv39 || sv54) &&
     (!sv10 || sv55 || sv70) && (!sv22 || sv44 || sv34) &&
     (sv1 || !sv24 || sv70) && (sv73 || sv67 || !sv56) &&
     (sv25 || !sv32 || sv72) && (sv6 || sv40 || !sv55) &&
     (!sv70 || !sv72 || sv52) && (sv55 || sv22 || !sv40) &&
     (!sv33 || !sv47 || !sv73) && (!sv6 || !sv15 || !sv22) &&
     (sv30 || sv72 || sv15) && (!sv9 || sv57 || !sv47) &&
     (sv36 || sv28 || !sv63) && (sv39 || !sv17 || sv70) &&
     (!sv2 || sv18 || !sv61) && (sv10 || sv40 || !sv21) &&
     (!sv17 || sv57 || sv58) && (sv44 || sv45 || !sv34) &&
     (sv7 || sv67 || !sv61) && (!sv68 || sv45 || !sv6) &&
     (!sv73 || sv53 || !sv17) && (!sv24 || sv9 || sv36) &&
     (sv15 || sv8 || sv3) && (!sv19 || !sv2 || sv69) &&
     (!sv28 || sv8 || !sv49) && (!sv57 || sv34 || !sv39) &&
     (sv49 || sv71 || !sv65) && (sv38 || !sv55 || sv3) &&
     (!sv65 || sv13 || !sv14) && (!sv50 || !sv16 || !sv59) &&
     (sv38 || !sv10 || !sv41) && (sv35 || sv22 || !sv41) &&
     (sv30 || !sv27 || !sv54) && (!sv42 || sv24 || !sv44) &&
     (!sv24 || sv21 || sv18) && (sv35 || !sv27 || sv67) &&
     (!sv45 || !sv7 || sv14) && (!sv6 || !sv7 || sv38) &&
     (sv61 || !sv26 || !sv68) && (sv23 || sv22 || sv70) &&
     (sv35 || !sv22 || !sv55) && (sv8 || sv5 || sv37) &&
     (sv57 || !sv20 || !sv24) && (sv55 || !sv10 || sv24) &&
     (sv59 || sv53 || sv7) && (!sv4 || !sv55 || sv65) &&
     (!sv36 || !sv67 || !sv74) && (!sv19 || sv56 || sv48) &&
     (!sv27 || sv66 || !sv22) && (sv7 || !sv35 || sv70) &&
     (!sv65 || sv8 || sv70) && (sv63 || !sv45 || sv62) &&
     (!sv18 || sv69 || !sv13) && (!sv32 || !sv39 || !sv47) &&
     (!sv69 || !sv19 || sv72) && (sv40 || sv63 || !sv22) &&
     (sv9 || sv55 || !sv71) && (sv12 || sv29 || !sv24) &&
     (!sv31 || !sv59 || !sv53) && (!sv39 || !sv61 || sv52) &&
     (!sv43 || sv69 || !sv26) && (!sv64 || !sv12 || !sv30) &&
     (!sv9 || sv37 || sv7) && (!sv67 || sv9 || !sv50) &&
     (!sv17 || sv69 || sv46) && (!sv19 || !sv34 || !sv6) &&
     (!sv38 || !sv71 || sv26) && (sv34 || !sv53 || sv27) &&
     (!sv65 || sv28 || sv36) && (!sv29 || sv30 || sv9) &&
     (!sv36 || !sv54 || !sv44) && (sv19 || sv74 || !sv65) &&
     (sv44 || sv43 || !sv9) && (!sv58 || sv34 || sv11) &&
     (sv49 || !sv52 || !sv64) && (sv71 || sv59 || !sv51) &&
     (!sv60 || !sv49 || sv21) && (sv54 || !sv12 || sv62) &&
     (sv73 || sv26 || sv6) && (!sv59 || sv46 || sv53) &&
     (sv36 || !sv31 || sv74) && (!sv25 || !sv11 || !sv9) &&
     (!sv8 || !sv64 || sv41) && (sv8 || sv48 || sv40) &&
     (!sv12 || sv50 || sv8) && (sv69 || sv52 || sv60) &&
     (sv14 || sv32 || !sv65) && (sv63 || sv20 || !sv57) &&
     (!sv7 || sv61 || sv58) && (sv53 || sv31 || !sv24) &&
     (!sv69 || sv65 || !sv17) && (sv11 || sv51 || sv31) &&
     (sv43 || sv3 || sv39) && (!sv54 || !sv25 || !sv20) &&
     (!sv4 || sv31 || !sv73) && (sv67 || !sv22 || sv46) &&
     (sv68 || sv22 || !sv32) && (!sv49 || !sv64 || !sv58) &&
     (sv3 || sv31 || !sv70) && (sv70 || sv8 || !sv33) &&
     (sv14 || !sv46 || !sv60) && (sv63 || !sv27 || sv57) &&
     (sv11 || !sv3 || sv19) && (sv12 || sv48 || sv70) &&
     (sv36 || sv64 || sv48) && (!sv29 || !sv26 || !sv2) &&
     (!sv29 || sv15 || sv56))) {
            char bounded_buf[32];
            if (strlen(checked_name) >= sizeof(bounded_buf)) {
                printf("display name too long\n");
                return -1;
            }
            strcpy(bounded_buf, checked_name);
            printf("display name: %s\n", bounded_buf);
            return (int)strlen(bounded_buf);
    } else {
            char bounded_buf[32];
            if (strlen(checked_name) >= sizeof(bounded_buf)) {
                printf("display name too long\n");
                return -1;
            }
            strcpy(bounded_buf, checked_name);
            printf("display name: %s\n", bounded_buf);
            return (int)strlen(bounded_buf);
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
