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
    int ctx_tag = (int)(strlen(username) % 13);
    if ((ctx_tag * ctx_tag + 2 * ctx_tag + 1) == (ctx_tag + 1) * (ctx_tag + 1)) {
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
