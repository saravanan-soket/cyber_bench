// vuln.c — A program with a heap-buffer-overflow bug.
// Reads input file into a temporary buffer, then copies into
// a too-small heap allocation. Triggers on inputs > 16 bytes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Prevent the compiler from optimizing away the overflow.
void __attribute__((noinline)) process(char *dst, const char *src, long n) {
    for (long i = 0; i < n; i++) {
        dst[i] = src[i]; // heap-buffer-overflow when i >= 16
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

    // BUG: fixed-size 16-byte buffer
    char *buf = (char *)malloc(16);
    process(buf, input, size);

    printf("processed %ld bytes\n", size);
    free(buf);
    free(input);
    return 0;
}
