// fixed.c — The patched version. Allocates the right size.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void __attribute__((noinline)) process(char *dst, const char *src, long n) {
    for (long i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *input = (char *)malloc(size);
    fread(input, 1, size, f);
    fclose(f);

    // FIX: allocate enough space
    char *buf = (char *)malloc(size > 0 ? size : 1);
    process(buf, input, size);

    printf("processed %ld bytes\n", size);
    free(buf);
    free(input);
    return 0;
}
