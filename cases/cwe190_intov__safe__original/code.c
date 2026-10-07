#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/* Builds a lookup table with `count` entries. */
int *make_table(int count) {
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
