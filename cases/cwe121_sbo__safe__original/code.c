#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Profile service: stores the user's display name. */
int set_display_name(const char *name) {
    char buf[32];
    if (strlen(name) >= sizeof(buf)) {
        printf("display name too long\n");
        return -1;
    }
    strcpy(buf, name);
    printf("display name: %s\n", buf);
    return (int)strlen(buf);
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
