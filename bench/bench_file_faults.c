#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static size_t parse_size(const char *s) {
    char *end;
    size_t v = strtoull(s, &end, 10);
    switch (*end) {
        case 'G': case 'g': return v * 1024ULL * 1024ULL * 1024ULL;
        case 'M': case 'm': return v * 1024ULL * 1024ULL;
        case 'K': case 'k': return v * 1024ULL;
        case '\0': return v;
        default:
            fprintf(stderr, "Invalid size suffix: %s\n", s);
            exit(1);
    }
}

static void access_sequential(char *p, size_t size, size_t pagesize) {
    for (size_t off = 0; off < size; off += pagesize) {
        volatile char x = p[off];
        (void)x;
    }
}

int main(int argc, char **argv) {
    size_t size = 256 * 1024 * 1024; // default 256MB
    const char *pattern = "seq";

    // -------- CLI args --------
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--size") && i+1 < argc) {
            size = parse_size(argv[++i]);
        } else if (!strcmp(argv[i], "--pattern") && i+1 < argc) {
            pattern = argv[++i];
        } else {
            fprintf(stderr, "Usage: %s [--size N] [--pattern seq]\n", argv[0]);
            return 1;
        }
    }

    printf("[bench] Using size = %zu bytes\n", size);
    printf("[bench] Pattern   = %s\n", pattern);

    size_t pagesize = getpagesize();

    // -------- Create test file --------
    int fd = open("testfile.bin", O_RDWR | O_CREAT, 0666);
    if (fd < 0) die("open testfile");

    if (ftruncate(fd, size) < 0) die("ftruncate");

    // -------- Evict from page cache (forces major faults) --------
    if (posix_fadvise(fd, 0, size, POSIX_FADV_DONTNEED) != 0)
        die("posix_fadvise");

    // -------- Map file --------
    char *p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) die("mmap file");

    printf("[bench] File mapped. Starting access...\n");

    // -------- Measure faults --------
    struct rusage before, after;
    getrusage(RUSAGE_SELF, &before);

    if (!strcmp(pattern, "seq"))
        access_sequential(p, size, pagesize);
    else {
        fprintf(stderr, "Unknown pattern: %s\n", pattern);
        exit(1);
    }

    getrusage(RUSAGE_SELF, &after);

    // -------- Report --------
    long minor = after.ru_minflt - before.ru_minflt;
    long major = after.ru_majflt - before.ru_majflt;

    printf("[bench] Finished.\n");
    printf("[bench] Minor faults: %ld\n", minor);
    printf("[bench] Major faults: %ld\n", major);

    munmap(p, size);
    close(fd);
    return 0;
}
