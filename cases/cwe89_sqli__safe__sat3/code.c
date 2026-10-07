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

int lookup_user(const char *username) {
    const int sv0 = 1, sv1 = 1, sv2 = 0, sv3 = 1, sv4 = 0, sv5 = 1, sv6 = 1,
              sv7 = 0, sv8 = 0, sv9 = 0, sv10 = 0, sv11 = 1, sv12 = 0, sv13 = 1,
              sv14 = 1, sv15 = 0, sv16 = 1, sv17 = 1, sv18 = 0, sv19 = 0;
    if ((!sv9 || sv2 || sv8) && (sv6 || !sv7 || sv2) && (sv12 || !sv4 || sv6) &&
     (!sv7 || sv18 || !sv17) && (sv4 || sv17 || !sv14) &&
     (sv5 || sv9 || !sv6) && (!sv15 || sv10 || sv0) && (sv5 || !sv13 || sv15) &&
     (sv10 || sv2 || sv17) && (!sv10 || !sv13 || sv17) &&
     (!sv7 || !sv5 || !sv3) && (sv18 || !sv6 || !sv19) &&
     (sv4 || !sv17 || !sv8) && (sv5 || sv11 || sv17) &&
     (sv9 || sv15 || !sv19) && (sv13 || !sv6 || sv12) && (sv4 || !sv8 || sv7) &&
     (sv15 || sv1 || sv10) && (!sv4 || sv0 || sv3) && (!sv6 || !sv10 || sv0) &&
     (!sv14 || sv13 || sv10) && (sv9 || !sv6 || !sv15) &&
     (sv13 || sv12 || !sv0) && (sv2 || sv5 || sv16) &&
     (!sv9 || !sv1 || !sv17) && (sv5 || sv9 || sv6) && (sv0 || sv10 || sv2) &&
     (sv15 || sv6 || !sv7) && (!sv4 || !sv16 || !sv10) &&
     (!sv11 || sv17 || sv13) && (!sv1 || sv6 || sv18) &&
     (sv13 || sv19 || sv4) && (!sv15 || !sv8 || !sv18) &&
     (sv6 || sv18 || sv5) && (!sv17 || !sv8 || !sv5) &&
     (!sv15 || sv19 || sv0) && (sv7 || sv5 || sv17) && (sv8 || !sv12 || !sv7) &&
     (!sv10 || !sv2 || !sv14) && (!sv10 || sv1 || sv11) &&
     (sv12 || sv5 || !sv17) && (sv0 || !sv19 || !sv2) &&
     (!sv17 || sv18 || sv13) && (sv8 || !sv16 || sv1) &&
     (sv5 || sv4 || !sv12) && (sv10 || !sv0 || sv1) &&
     (sv13 || sv17 || !sv18) && (sv16 || sv10 || !sv8) &&
     (!sv6 || !sv2 || !sv13) && (!sv9 || sv17 || sv2) &&
     (sv15 || !sv9 || sv17) && (!sv8 || sv14 || sv3) &&
     (!sv0 || !sv4 || !sv15) && (sv10 || !sv8 || sv3) &&
     (sv10 || !sv8 || !sv1) && (!sv2 || !sv9 || !sv11) &&
     (sv7 || !sv13 || !sv4) && (sv9 || sv0 || sv12) &&
     (!sv12 || !sv2 || sv14) && (!sv0 || sv6 || sv8) &&
     (sv16 || !sv9 || !sv3) && (!sv9 || sv3 || !sv16) &&
     (sv7 || sv17 || !sv10) && (sv4 || !sv1 || !sv7) &&
     (!sv11 || !sv17 || !sv9) && (!sv14 || sv2 || sv5) &&
     (!sv10 || !sv12 || !sv1) && (!sv8 || !sv6 || sv3) &&
     (sv19 || !sv17 || !sv10) && (!sv10 || sv15 || !sv9) &&
     (sv7 || sv8 || !sv9) && (sv4 || sv18 || !sv10) && (!sv13 || sv5 || sv9) &&
     (!sv15 || !sv12 || sv7) && (!sv13 || sv0 || !sv10) &&
     (sv5 || sv3 || !sv19) && (sv15 || sv0 || sv13) &&
     (!sv0 || !sv14 || !sv15) && (sv7 || !sv13 || sv16) &&
     (!sv18 || sv3 || !sv17) && (sv9 || !sv1 || !sv18) &&
     (!sv15 || sv17 || !sv19) && (sv12 || sv6 || !sv1) &&
     (sv11 || !sv6 || !sv9) && (!sv9 || !sv10 || !sv13)) {
            const char *query = "SELECT id, email FROM users WHERE name = ?";
            return db_exec_param(query, username);
    } else {
            const char *query = "SELECT id, email FROM users WHERE name = ?";
            return db_exec_param(query, username);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <username>\n", argv[0]);
        return 2;
    }
    return lookup_user(argv[1]);
}
