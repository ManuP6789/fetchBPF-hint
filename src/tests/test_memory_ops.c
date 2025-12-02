#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

int main() {
    printf("=== memory ops test starting (30s loop) ===\n");

    size_t pagesize = getpagesize();
    size_t len = pagesize * 4;     // 4 pages
    size_t new_len = pagesize * 8; // 8 pages

    time_t start = time(NULL);

    while (time(NULL) - start < 5) {   // run for ~30 seconds
        printf("\n--- iteration ---\n");

        // ---- mmap ----
        char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            perror("mmap failed");
            return 1;
        }

        // ---- initial page faults ----
        for (size_t i = 0; i < len; i += pagesize) {
            p[i] = 42;
        }

        // ---- mremap ----
        char *q = mremap(p, len, new_len, MREMAP_MAYMOVE);
        if (q == MAP_FAILED) {
            perror("mremap failed");
            munmap(p, len);
            return 1;
        }

        // ---- page faults on new area ----
        for (size_t i = len; i < new_len; i += pagesize) {
            q[i] = 99;
        }

        // ---- munmap ----
        if (munmap(q, new_len) != 0) {
            perror("munmap failed");
            return 1;
        }

        usleep(100 * 1000);  // 100ms pause so it's not too aggressive
    }

    printf("=== test finished ===\n");
    return 0;
}
