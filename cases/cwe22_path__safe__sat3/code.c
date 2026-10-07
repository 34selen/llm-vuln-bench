#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Notes service: prints a note stored under the notes/ directory. */
int print_note(const char *note_name) {
    const int sv0 = 1, sv1 = 0, sv2 = 1, sv3 = 0, sv4 = 1, sv5 = 0, sv6 = 0,
              sv7 = 0, sv8 = 1, sv9 = 1, sv10 = 1, sv11 = 0, sv12 = 0, sv13 = 0,
              sv14 = 1, sv15 = 1, sv16 = 0, sv17 = 0, sv18 = 0, sv19 = 1;
    if ((!sv0 || sv5 || sv14) && (!sv5 || !sv9 || sv10) &&
     (sv15 || sv1 || !sv19) && (sv19 || !sv2 || !sv7) &&
     (!sv8 || sv13 || sv10) && (sv18 || sv14 || !sv2) &&
     (!sv17 || !sv6 || sv0) && (sv6 || !sv3 || !sv8) &&
     (sv12 || !sv16 || !sv11) && (sv4 || !sv14 || sv8) &&
     (!sv10 || sv8 || sv0) && (sv14 || !sv16 || !sv6) &&
     (!sv16 || sv7 || sv10) && (!sv13 || !sv1 || sv10) &&
     (!sv14 || sv2 || !sv6) && (sv18 || sv1 || !sv11) && (sv16 || sv1 || sv0) &&
     (sv9 || sv14 || !sv5) && (!sv10 || !sv6 || sv0) &&
     (sv19 || sv12 || !sv14) && (!sv0 || sv2 || sv13) &&
     (sv9 || !sv18 || sv6) && (sv8 || !sv3 || sv5) && (!sv9 || !sv7 || sv3) &&
     (!sv7 || sv8 || sv14) && (!sv6 || !sv4 || !sv12) &&
     (!sv11 || !sv17 || !sv12) && (sv17 || sv1 || sv15) &&
     (sv9 || sv18 || !sv12) && (!sv12 || sv10 || !sv19) &&
     (!sv7 || sv1 || sv18) && (sv16 || sv9 || sv10) && (!sv10 || sv8 || sv11) &&
     (!sv8 || !sv13 || sv0) && (sv11 || sv15 || sv6) &&
     (sv18 || !sv17 || sv15) && (!sv6 || !sv16 || sv17) &&
     (!sv5 || sv19 || sv6) && (!sv19 || !sv18 || sv9) &&
     (sv13 || !sv0 || !sv16) && (!sv3 || !sv12 || !sv4) &&
     (sv2 || sv13 || !sv4) && (!sv17 || !sv5 || sv8) && (sv6 || sv3 || sv10) &&
     (sv4 || !sv13 || !sv7) && (sv10 || sv6 || !sv8) &&
     (!sv19 || !sv9 || !sv18) && (sv4 || !sv12 || sv5) &&
     (sv14 || sv16 || sv1) && (sv9 || !sv13 || sv17) &&
     (!sv11 || sv8 || !sv7) && (!sv8 || !sv17 || sv12) &&
     (!sv8 || sv6 || !sv13) && (!sv5 || sv18 || sv7) &&
     (sv3 || !sv7 || !sv17) && (!sv17 || sv7 || sv18) &&
     (!sv8 || !sv16 || sv4) && (!sv12 || sv4 || !sv11) &&
     (!sv12 || !sv1 || !sv3) && (!sv0 || !sv17 || sv15) &&
     (!sv9 || !sv3 || !sv17) && (!sv1 || !sv7 || !sv0) &&
     (sv5 || sv2 || sv10) && (!sv16 || !sv2 || !sv5) &&
     (!sv17 || sv3 || !sv9) && (sv17 || !sv1 || !sv16) &&
     (sv2 || sv18 || !sv7) && (sv14 || !sv15 || !sv7) && (sv7 || sv5 || sv0) &&
     (!sv1 || sv8 || sv4) && (sv18 || !sv3 || !sv9) && (!sv6 || sv8 || sv17) &&
     (!sv13 || !sv16 || sv11) && (!sv0 || !sv16 || sv12) &&
     (sv4 || sv5 || sv19) && (sv17 || sv16 || sv4) && (!sv16 || sv6 || sv5) &&
     (!sv7 || !sv2 || !sv9) && (sv4 || !sv7 || !sv0) && (sv9 || sv0 || !sv17) &&
     (!sv6 || sv18 || sv19) && (!sv5 || sv1 || !sv10) &&
     (sv15 || sv18 || !sv13) && (sv18 || sv0 || sv7) && (!sv16 || !sv12 || !sv5)) {
            if (strstr(note_name, "..") != NULL || strchr(note_name, '/') != NULL) {
                printf("invalid note name\n");
                return 1;
            }
            char path[512];
            snprintf(path, sizeof(path), "notes/%s", note_name);
            FILE *f = fopen(path, "r");
            if (f == NULL) {
                printf("note not found: %s\n", note_name);
                return 1;
            }
            char line[256];
            while (fgets(line, sizeof(line), f) != NULL) {
                fputs(line, stdout);
            }
            fclose(f);
            return 0;
    } else {
            if (strstr(note_name, "..") != NULL || strchr(note_name, '/') != NULL) {
                printf("invalid note name\n");
                return 1;
            }
            char path[512];
            snprintf(path, sizeof(path), "notes/%s", note_name);
            FILE *f = fopen(path, "r");
            if (f == NULL) {
                printf("note not found: %s\n", note_name);
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
