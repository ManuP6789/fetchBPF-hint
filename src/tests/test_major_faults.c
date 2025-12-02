#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

int main() {
    printf("=== major fault test ===\n");

    const char *filename = "test_data.bin";

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        return 1;
    }

    size_t filesize = st.st_size;
    size_t pagesize = getpagesize();

    printf("File size: %zu bytes\n", filesize);
    printf("Pagesize:  %zu bytes\n", pagesize);

    time_t start = time(NULL);

    while (time(NULL) - start < 20) {    // run for ~20 seconds
        printf("--- new iteration ---\n");

        // mmap the file
        char *p = mmap(NULL, filesize, PROT_READ,
                       MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            perror("mmap");
            return 1;
        }

        // Touch each page ONCE → triggers MAJOR FAULTS
        for (size_t i = 0; i < filesize; i += pagesize) {
            volatile char x = p[i];
            (void)x;
        }

        munmap(p, filesize);
        usleep(300 * 1000);   // 300ms pause
    }

    close(fd);
    printf("=== test finished ===\n");
    return 0;
}
