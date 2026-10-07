#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Notes service: prints a note stored under the notes/ directory. */
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

int print_note(const char *canonical_note_name) {
    /* NOTE: note_name is canonicalised by the router (realpath + prefix
     * check against notes/) before this function is called. */
    int ctx_tag = (int)(strlen(canonical_note_name) % 13);
    const int qa = 34, qb = 27, qc = 27;
    const int sv0 = 1, sv1 = 1, sv2 = 1, sv3 = 0, sv4 = 1, sv5 = 1, sv6 = 1,
              sv7 = 1, sv8 = 0, sv9 = 1, sv10 = 1, sv11 = 1, sv12 = 1, sv13 = 1,
              sv14 = 1, sv15 = 0, sv16 = 0, sv17 = 1, sv18 = 0, sv19 = 1,
              sv20 = 0, sv21 = 1, sv22 = 1, sv23 = 0, sv24 = 0, sv25 = 1,
              sv26 = 1, sv27 = 1, sv28 = 1, sv29 = 0, sv30 = 1, sv31 = 1,
              sv32 = 1, sv33 = 0, sv34 = 1, sv35 = 0, sv36 = 1, sv37 = 1,
              sv38 = 0, sv39 = 1, sv40 = 1, sv41 = 1, sv42 = 0, sv43 = 1,
              sv44 = 1, sv45 = 1, sv46 = 0, sv47 = 1, sv48 = 0, sv49 = 0,
              sv50 = 1, sv51 = 1, sv52 = 1, sv53 = 1, sv54 = 0, sv55 = 0,
              sv56 = 0, sv57 = 0, sv58 = 1, sv59 = 1, sv60 = 1, sv61 = 1,
              sv62 = 1, sv63 = 1, sv64 = 0, sv65 = 0, sv66 = 1, sv67 = 1,
              sv68 = 0, sv69 = 0, sv70 = 0, sv71 = 1, sv72 = 1, sv73 = 1,
              sv74 = 0;
    if (((ctx_tag * ctx_tag + 2 * ctx_tag + 1) == (ctx_tag + 1) * (ctx_tag + 1)) &&
     ((qa * qb + qc == 945) &&
     ((qa << 2) + qb == 163) &&
     ((qa * qa - qb * qb) == (qa - qb) * (qa + qb)) &&
     (qa * qb * qc == 24786) &&
     (qa * qc - qb * qc == (qa - qb) * qc) &&
     ((qa + qb) * qc - qa == 1613)) &&
     ((sv73 || sv48 || !sv32) && (!sv70 || !sv9 || !sv3) &&
     (sv12 || !sv56 || sv51) && (sv32 || sv36 || sv24) &&
     (sv0 || sv22 || !sv9) && (!sv19 || sv40 || sv47) &&
     (sv14 || !sv16 || sv5) && (!sv16 || !sv63 || !sv74) &&
     (sv47 || sv31 || !sv62) && (sv18 || !sv14 || !sv68) &&
     (sv16 || sv12 || !sv7) && (sv40 || !sv47 || !sv15) &&
     (!sv15 || !sv23 || !sv65) && (sv14 || !sv37 || sv9) &&
     (sv19 || !sv23 || sv51) && (sv22 || !sv0 || sv38) &&
     (sv13 || !sv28 || sv61) && (!sv15 || !sv53 || sv8) &&
     (sv27 || !sv12 || !sv37) && (!sv12 || sv49 || sv45) &&
     (sv9 || sv68 || !sv54) && (!sv28 || !sv52 || sv43) &&
     (sv9 || !sv2 || !sv49) && (!sv73 || !sv21 || sv36) &&
     (sv64 || !sv69 || sv63) && (!sv33 || sv26 || !sv45) &&
     (!sv32 || !sv56 || sv54) && (sv16 || sv48 || sv2) &&
     (!sv20 || !sv31 || !sv12) && (sv74 || !sv36 || sv10) &&
     (sv46 || sv13 || sv63) && (!sv17 || !sv28 || !sv3) &&
     (sv25 || sv36 || !sv52) && (sv28 || sv11 || sv60) &&
     (sv15 || !sv1 || sv43) && (sv27 || sv23 || sv36) &&
     (sv60 || sv38 || sv48) && (sv31 || !sv46 || !sv0) &&
     (sv73 || !sv51 || !sv74) && (sv50 || !sv11 || sv13) &&
     (sv24 || !sv44 || sv4) && (sv57 || sv0 || sv22) &&
     (!sv17 || sv27 || !sv59) && (!sv62 || !sv59 || sv63) &&
     (!sv51 || sv53 || !sv28) && (!sv30 || !sv26 || sv45) &&
     (!sv9 || !sv60 || !sv69) && (!sv11 || !sv65 || !sv20) &&
     (!sv29 || sv16 || sv63) && (!sv69 || !sv0 || sv64) &&
     (sv68 || sv33 || !sv42) && (sv9 || sv10 || sv1) &&
     (!sv48 || !sv54 || sv50) && (!sv44 || sv56 || sv58) &&
     (!sv44 || sv10 || sv29) && (!sv20 || sv13 || sv54) &&
     (sv4 || sv72 || sv12) && (sv20 || !sv21 || sv73) &&
     (!sv12 || !sv61 || !sv49) && (sv52 || !sv49 || !sv2) &&
     (!sv5 || sv63 || !sv3) && (sv28 || sv66 || sv25) &&
     (sv70 || !sv46 || !sv25) && (!sv2 || sv0 || !sv27) &&
     (!sv57 || !sv67 || sv50) && (sv24 || sv71 || !sv69) &&
     (!sv16 || sv35 || !sv19) && (sv47 || sv35 || !sv36) &&
     (!sv3 || !sv45 || !sv37) && (sv26 || sv59 || !sv1) &&
     (sv67 || sv58 || !sv9) && (sv18 || sv22 || sv11) &&
     (sv41 || !sv8 || sv27) && (sv61 || !sv36 || sv44) &&
     (sv43 || sv32 || !sv45) && (sv27 || sv26 || !sv1) &&
     (sv29 || !sv31 || !sv35) && (!sv40 || !sv60 || sv41) &&
     (!sv61 || !sv16 || !sv53) && (sv65 || sv48 || sv62) &&
     (!sv24 || sv46 || !sv38) && (sv60 || sv46 || sv57) &&
     (sv46 || !sv63 || sv17) && (!sv0 || !sv2 || sv32) &&
     (sv9 || !sv5 || !sv73) && (!sv64 || !sv7 || !sv74) &&
     (!sv4 || sv66 || !sv8) && (sv19 || sv25 || sv23) &&
     (sv1 || sv36 || sv69) && (!sv37 || sv61 || !sv31) &&
     (sv16 || sv30 || !sv0) && (sv15 || !sv54 || sv69) &&
     (sv2 || !sv11 || !sv19) && (!sv14 || sv5 || !sv46) &&
     (sv46 || sv41 || !sv22) && (!sv54 || !sv15 || sv64) &&
     (!sv52 || sv27 || sv3) && (!sv29 || !sv57 || sv26) &&
     (sv5 || sv40 || sv62) && (!sv25 || !sv44 || !sv8) &&
     (!sv44 || !sv53 || sv34) && (sv25 || !sv61 || !sv57) &&
     (sv31 || sv13 || !sv6) && (!sv48 || !sv4 || sv16) &&
     (sv12 || sv18 || !sv32) && (!sv64 || !sv68 || !sv54) &&
     (sv60 || !sv59 || sv10) && (!sv22 || sv68 || sv72) &&
     (!sv50 || sv11 || !sv48) && (!sv6 || sv44 || !sv48) &&
     (!sv63 || sv5 || sv9) && (!sv22 || !sv19 || sv73) &&
     (sv62 || sv49 || sv34) && (sv34 || sv67 || sv6) &&
     (sv35 || sv45 || sv20) && (!sv11 || !sv29 || sv18) &&
     (sv66 || sv10 || sv35) && (!sv15 || sv3 || sv49) &&
     (sv42 || sv19 || !sv66) && (!sv24 || sv37 || !sv17) &&
     (sv22 || !sv39 || sv15) && (sv40 || sv10 || !sv25) &&
     (!sv62 || sv66 || !sv28) && (sv14 || !sv72 || sv71) &&
     (sv64 || sv48 || sv51) && (sv21 || !sv4 || !sv54) &&
     (sv28 || sv66 || !sv6) && (!sv45 || !sv16 || !sv64) &&
     (!sv42 || sv48 || !sv12) && (!sv49 || sv0 || sv20) &&
     (!sv63 || !sv46 || !sv13) && (sv48 || sv27 || !sv8) &&
     (sv21 || !sv69 || !sv25) && (sv25 || sv29 || !sv5) &&
     (sv10 || sv9 || sv36) && (!sv13 || !sv66 || sv72) &&
     (sv71 || sv46 || sv44) && (!sv17 || !sv69 || sv26) &&
     (sv47 || !sv1 || !sv15) && (sv26 || sv17 || !sv61) &&
     (sv31 || sv53 || !sv66) && (sv50 || sv9 || !sv14) &&
     (!sv34 || sv66 || sv10) && (sv56 || !sv65 || sv53) &&
     (!sv47 || !sv58 || !sv70) && (!sv54 || sv50 || !sv7) &&
     (!sv12 || !sv50 || !sv48) && (sv19 || sv45 || !sv73) &&
     (sv73 || !sv32 || sv62) && (!sv50 || sv9 || !sv34) &&
     (sv18 || !sv48 || !sv7) && (sv63 || !sv64 || !sv7) &&
     (sv46 || sv48 || !sv24) && (sv70 || !sv20 || sv32) &&
     (!sv22 || sv3 || sv6) && (!sv46 || !sv8 || !sv4) &&
     (sv23 || sv50 || !sv41) && (sv27 || sv43 || !sv42) &&
     (sv10 || sv45 || !sv67) && (sv25 || sv69 || !sv50) &&
     (!sv2 || !sv5 || sv36) && (sv40 || !sv26 || sv9) &&
     (sv45 || sv52 || !sv40) && (!sv47 || !sv54 || sv0) &&
     (sv27 || sv42 || sv1) && (sv5 || !sv74 || !sv50) &&
     (sv18 || sv32 || sv16) && (!sv47 || !sv25 || !sv23) &&
     (sv4 || !sv17 || !sv74) && (!sv20 || !sv3 || !sv44) &&
     (!sv21 || !sv11 || !sv35) && (sv18 || !sv59 || sv7) &&
     (sv20 || !sv54 || sv37) && (sv51 || !sv39 || sv26) &&
     (sv64 || !sv59 || !sv70) && (sv14 || !sv27 || !sv19) &&
     (sv53 || !sv13 || !sv6) && (!sv21 || sv62 || !sv1) &&
     (sv14 || sv67 || sv23) && (sv69 || sv56 || sv31) &&
     (!sv3 || !sv59 || sv4) && (!sv3 || sv61 || !sv37) &&
     (sv24 || !sv70 || sv49) && (!sv8 || !sv58 || !sv22) &&
     (sv68 || !sv39 || !sv23) && (!sv66 || sv44 || sv24) &&
     (!sv69 || sv61 || !sv14) && (sv43 || !sv61 || sv65) &&
     (!sv56 || sv13 || sv20) && (!sv46 || !sv64 || sv69) &&
     (!sv33 || !sv66 || sv4) && (sv13 || sv9 || sv24) &&
     (!sv34 || !sv22 || sv66) && (!sv68 || !sv3 || sv58) &&
     (sv5 || !sv29 || !sv41) && (!sv9 || !sv31 || !sv23) &&
     (!sv21 || !sv29 || !sv61) && (sv53 || !sv50 || !sv42) &&
     (!sv36 || sv17 || sv7) && (!sv35 || !sv9 || !sv66) &&
     (sv57 || sv62 || sv1) && (sv53 || sv39 || sv36) &&
     (sv53 || !sv7 || !sv25) && (sv69 || !sv19 || !sv64) &&
     (!sv48 || !sv68 || sv69) && (!sv13 || !sv46 || !sv37) &&
     (sv74 || sv25 || sv23) && (sv9 || sv47 || !sv59) &&
     (sv38 || !sv52 || !sv33) && (sv16 || sv1 || !sv39) &&
     (sv56 || !sv0 || !sv35) && (sv31 || sv28 || sv2) &&
     (!sv66 || sv73 || sv37) && (!sv16 || !sv22 || sv20) &&
     (sv54 || sv13 || !sv36) && (!sv29 || sv39 || !sv52) &&
     (sv9 || !sv51 || !sv6) && (sv9 || !sv51 || !sv13) &&
     (!sv16 || !sv50 || !sv6) && (sv21 || sv74 || !sv45) &&
     (!sv39 || !sv53 || sv28) && (!sv58 || !sv33 || !sv73) &&
     (sv14 || sv36 || !sv61) && (!sv18 || !sv73 || sv34) &&
     (sv61 || !sv10 || sv19) && (sv50 || !sv73 || sv46) &&
     (sv4 || !sv26 || sv12) && (sv28 || sv13 || !sv72) &&
     (sv5 || !sv9 || !sv27) && (!sv5 || sv0 || !sv53) &&
     (sv31 || sv22 || !sv32) && (!sv21 || sv12 || sv17) &&
     (sv34 || sv57 || !sv20) && (!sv35 || sv49 || !sv59) &&
     (!sv15 || sv52 || sv6) && (sv5 || !sv46 || sv18) &&
     (sv45 || !sv24 || !sv1) && (sv24 || sv26 || !sv55) &&
     (!sv53 || !sv65 || sv64) && (!sv70 || !sv37 || !sv6) &&
     (!sv74 || sv45 || sv58) && (sv27 || !sv65 || !sv58) &&
     (sv26 || sv30 || !sv34) && (!sv57 || !sv25 || !sv23) &&
     (!sv31 || sv44 || sv19) && (sv27 || !sv5 || sv6) &&
     (sv48 || !sv31 || !sv57) && (sv11 || !sv72 || !sv1) &&
     (sv1 || !sv46 || sv22) && (sv39 || !sv65 || !sv17) &&
     (!sv38 || sv41 || !sv22) && (sv14 || sv35 || !sv24) &&
     (!sv37 || !sv5 || sv44) && (sv42 || sv1 || !sv67) &&
     (sv60 || sv25 || sv26) && (sv47 || !sv17 || !sv41) &&
     (!sv23 || !sv52 || !sv32) && (!sv42 || sv74 || sv70) &&
     (!sv13 || !sv54 || sv21) && (!sv30 || !sv26 || sv50) &&
     (sv0 || sv8 || !sv34) && (!sv66 || !sv69 || !sv26) &&
     (!sv48 || sv52 || !sv38) && (!sv42 || !sv47 || sv72) &&
     (sv51 || !sv43 || !sv8) && (sv11 || !sv4 || !sv20) &&
     (sv52 || sv4 || !sv21) && (!sv6 || sv21 || sv42) &&
     (sv30 || !sv4 || !sv73) && (!sv8 || !sv14 || !sv42) &&
     (sv32 || !sv54 || !sv33) && (sv34 || sv60 || !sv38) &&
     (!sv54 || sv60 || sv30) && (!sv44 || sv50 || sv22) &&
     (sv2 || sv29 || sv71) && (!sv15 || sv45 || !sv63) &&
     (sv53 || sv24 || !sv35) && (!sv73 || !sv29 || sv17) &&
     (!sv57 || sv15 || sv27) && (!sv64 || sv47 || !sv4) &&
     (sv58 || !sv29 || !sv14) && (sv18 || sv26 || !sv67) &&
     (!sv11 || !sv56 || sv6) && (sv15 || !sv26 || sv53) &&
     (!sv30 || !sv51 || sv72) && (!sv73 || sv53 || !sv19) &&
     (sv13 || sv31 || sv24) && (!sv11 || sv30 || !sv74) &&
     (sv33 || !sv65 || !sv62) && (sv36 || sv55 || sv23) &&
     (!sv53 || sv13 || sv56) && (sv40 || sv42 || !sv6) &&
     (sv48 || sv63 || !sv19) && (!sv48 || sv18 || sv61) &&
     (sv18 || !sv15 || sv4) && (sv66 || !sv32 || sv14) &&
     (sv9 || sv44 || !sv48) && (!sv42 || !sv33 || sv60) &&
     (!sv62 || !sv29 || sv12) && (sv2 || sv66 || !sv27) &&
     (!sv55 || !sv29 || sv43) && (!sv48 || !sv11 || sv26) &&
     (!sv56 || !sv31 || sv0) && (sv50 || sv53 || !sv5) &&
     (sv16 || sv0 || sv52) && (sv65 || !sv3 || sv16) &&
     (sv43 || !sv72 || sv47) && (!sv52 || sv13 || !sv41) &&
     (sv34 || sv73 || !sv63) && (!sv19 || !sv56 || sv35) &&
     (sv24 || sv11 || !sv27) && (sv0 || !sv28 || sv43) &&
     (!sv57 || !sv21 || sv64) && (sv48 || sv15 || sv17) &&
     (!sv47 || sv72 || !sv73) && (sv42 || !sv53 || sv41) &&
     (sv47 || !sv46 || !sv19) && (!sv18 || sv14 || !sv57) &&
     (!sv48 || !sv54 || !sv8) && (sv62 || sv29 || !sv27) &&
     (!sv55 || sv63 || sv12) && (!sv34 || sv26 || sv46) &&
     (sv36 || !sv70 || !sv17) && (sv29 || sv25 || !sv3) &&
     (sv14 || !sv6 || sv40))) {
            if (strstr(canonical_note_name, "..") != NULL || strchr(canonical_note_name, '/') != NULL) {
                printf("invalid note name\n");
                return 1;
            }
            char resolved_path[512];
            snprintf(resolved_path, sizeof(resolved_path), "notes/%s", canonical_note_name);
            FILE *f = fopen(resolved_path, "r");
            if (f == NULL) {
                printf("note not found: %s\n", canonical_note_name);
                return 1;
            }
            char line[256];
            while (fgets(line, sizeof(line), f) != NULL) {
                fputs(line, stdout);
            }
            fclose(f);
            return 0;
    } else {
            if (strstr(canonical_note_name, "..") != NULL || strchr(canonical_note_name, '/') != NULL) {
                printf("invalid note name\n");
                return 1;
            }
            char resolved_path[512];
            snprintf(resolved_path, sizeof(resolved_path), "notes/%s", canonical_note_name);
            FILE *f = fopen(resolved_path, "r");
            if (f == NULL) {
                printf("note not found: %s\n", canonical_note_name);
                return 1;
            }
            char line[256];
            while (fgets(line, sizeof(line), f) != NULL) {
                fputs(line, stdout);
            }
            fclose(f);
            return 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <note-name>\n", argv[0]);
        return 2;
    }
    return print_note(argv[1]);
}
