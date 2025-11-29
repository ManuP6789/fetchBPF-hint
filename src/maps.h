#ifndef MAPS_H
#define MAPS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PATH_MAX_MAP 512
typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint64_t inode;
    char pathname[PATH_MAX_MAP]; 
    bool file_backed;
} map_region_t;

typedef struct maps_cache maps_cache_t;

/* create/parse initial maps */
maps_cache_t *maps_load_from_pid(pid_t pid);

/* refresh after mmap/munmap if needed */
int maps_reload(maps_cache_t *cache, pid_t pid);

/* lookup region for given addr */
const map_region_t *maps_lookup(maps_cache_t *cache, uint64_t addr);

/* free */
void maps_free(maps_cache_t *cache);

#endif
