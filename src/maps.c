#include "maps.h"
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

struct maps_cache {
    size_t count;
    pid_t pid;
    map_region_t *regions;
};

int cmp_regions(const void *a, const void *b) {
    const map_region_t *ra = a;
    const map_region_t *rb = b;
    return (ra->start > rb->start) - (ra->start < rb->start);
}

static map_region_t parse_maps_line(const char *line) {
    map_region_t r;
    memset(&r, 0, sizeof(r));

    unsigned long long start, end, offset, inode;
    unsigned int dev_major, dev_minor;

    char perms[5];

    int n = sscanf(line,
                   "%llx-%llx %4s %llx %x:%x %llu",
                   &start, &end, perms, &offset,
                   &dev_major, &dev_minor, &inode);

    if (n < 7) {
        return r;
    }

    r.start = start;
    r.end = end;
    r.offset = offset;
    r.inode = inode;
    r.fd = -1;
    
    // Extract pathname: it's the part after the 6 fields
    const char *p = line;

    for (int i = 0; i < 5; i++) {
        p = strchr(p, ' ');
        if (!p) {
            r.pathname[0] = '\0';
            return r;
        }
        while (*p == ' ') p++; 
    }

    if (*p == '\0' || *p == '\n') {
        r.pathname[0] = '\0';
        r.file_backed = false;
        return r;
    }

    strncpy(r.pathname, p, PATH_MAX_MAP - 1);
    r.pathname[PATH_MAX_MAP - 1] = '\0';

    size_t L = strlen(r.pathname);
    if (L > 0 && r.pathname[L - 1] == '\n')
        r.pathname[L - 1] = '\0';

    // file-backed detection: inode > 0 AND absolute path
    if (r.inode > 0 && r.pathname[0] == '/')
        r.file_backed = true;
    else
        r.file_backed = false;

    return r;
}

maps_cache_t* maps_load_from_pid(pid_t pid) {
    char path[64];
    char line[512];
    sprintf(path, "/proc/%d/maps", pid);
    map_region_t *regions = NULL;
    size_t count = 0;
    maps_cache_t *cache = malloc(sizeof(maps_cache_t));
    if (!cache) {
        perror("calloc");
        return NULL;
    }
    cache->regions = NULL;
    cache->count = 0;

    // open /proc/<pid>/maps
    int fd = open(path, O_RDONLY);

    if (fd < 0) {
        perror("open /proc/<pid>/maps failed");
        return cache;   // empty cache
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        perror("fdopen failed");
        close(fd);
        return cache;
    }

    // parse each line
    while (fgets(line, sizeof(line), fp)) {
        regions = realloc(regions, (count+1) * sizeof(map_region_t));
        regions[count++] = parse_maps_line(line);
        printf("Read line: %s", line);
    }
    // fill map_region_t entries
    qsort(regions, count, sizeof(map_region_t), cmp_regions);
    cache->regions = regions;
    cache->count = count;
    cache->pid = pid;

    return cache;
}

int maps_reload(maps_cache_t *cache) {
    char path[64];
    char line[512];
    sprintf(path, "/proc/%d/maps", cache->pid);

    map_region_t *new_regions = NULL;
    size_t new_count = 0;

    int fd = open(path, O_RDONLY);

    if (fd < 0) {
        perror("open /proc/<pid>/maps failed, returning old cache");
        return -1;   // old cache
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        perror("fdopen failed");
        close(fd);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        new_regions = realloc(new_regions, (new_count+1) * sizeof(map_region_t));
        new_regions[new_count++] = parse_maps_line(line);
    }

    qsort(new_regions, new_count, sizeof(map_region_t), cmp_regions);

    // free old regions memory
    free(cache->regions);
    cache->regions = new_regions;
    cache->count = new_count;
    return 0;
}

map_region_t *maps_lookup(maps_cache_t *cache, uint64_t addr) {
    map_region_t key = {.start = addr};
    map_region_t *r = bsearch(
        &key,
        cache,
        cache->count,
        sizeof(map_region_t),
        cmp_regions
    );
    return r;
}


void maps_free(maps_cache_t *cache) {
    if (!cache) return;
    for (int i = 0; i < cache->count; i++) {
        
    }
    free(cache->regions);  
    free(cache);            
}


