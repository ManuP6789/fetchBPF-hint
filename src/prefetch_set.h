#ifndef PREFETCH_SET_H
#define PREFETCH_SET_H

#include <stdint.h>
#include "khash.h"

KHASH_SET_INIT_INT(prefetch)
KHASH_SET_INIT_INT64(page_set)


typedef khash_t(prefetch) prefetch_set_t;

prefetch_set_t *prefetch_set_create(void);
void prefetch_set_destroy(prefetch_set_t *set);

int prefetch_set_add(prefetch_set_t *set, uint64_t page);
int prefetch_set_contains(prefetch_set_t *set, uint64_t page);
int prefetch_set_remove(prefetch_set_t *set, uint64_t page);

#endif
