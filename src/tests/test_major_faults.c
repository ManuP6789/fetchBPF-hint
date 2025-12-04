#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>

double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

int main() {
    printf("=== major fault test ===\n");
    const char *filename = "test_data.bin";
    int fd = open(filename, O_RDONLY | O_DIRECT);
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
    printf("Pagesize: %zu bytes\n", pagesize);

    double total_page_access_time = 0.0;
    unsigned long total_faults = 0;
    double test_start = get_time_ms();

    time_t start = time(NULL);
    // while (time(NULL) - start < 20) { // run for ~20 seconds
    printf("--- new iteration ---\n");
    
    // posix_fadvise(fd, 0, filesize, POSIX_FADV_DONTNEED);
    posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);

    // mmap the file
    char *p = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    madvise(p, filesize, MADV_NOHUGEPAGE);

    // Touch each page ONCE → triggers MAJOR FAULTS
    double iter_start = get_time_ms();
    for (size_t i = 0; i < filesize; i += pagesize) {
        volatile char x = p[i];
        // if (i % (32 * pagesize) == 0)  // print every 32 pages
        //     printf("Accessing offset: %zu (page %lu)\n", i, i / pagesize);
        (void)x;
    }
    double iter_end = get_time_ms();
    double iter_time = iter_end - iter_start;
    
    unsigned long pages_accessed = filesize / pagesize;
    total_page_access_time += iter_time;
    total_faults += pages_accessed;
    
    printf("Iteration time: %.2f ms (%.2f ms per page)\n", 
            iter_time, iter_time / pages_accessed);

    munmap(p, filesize);
    usleep(300 * 1000); // 300ms pause
    // }

    double test_end = get_time_ms();
    double total_time = test_end - test_start;

    close(fd);
    printf("=== test finished ===\n");
    // printf("Total elapsed time: %.2f seconds\n", total_time / 1000.0);
    // printf("Total page access time: %.2f ms\n", total_page_access_time);
    // printf("Total faults triggered: %lu\n", total_faults);
    // printf("Average time per fault: %.3f ms\n", 
    //        total_page_access_time / total_faults);

    return 0;
}