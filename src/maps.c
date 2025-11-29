#include "maps.h"
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

struct maps_cache {
    map_region_t *regions;
    size_t count;
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

    return cache;
}

int maps_reload(maps_cache_t *cache, pid_t pid) {
    return 0;
}

const map_region_t *maps_lookup(maps_cache_t *cache, uint64_t addr) {
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

    free(cache->regions);  
    free(cache);            
}


