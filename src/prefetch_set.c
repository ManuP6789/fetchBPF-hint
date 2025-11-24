#include "prefetch_set.h"

prefetch_set_t *prefetch_set_create(void) {
    return kh_init(prefetch);
}

void prefetch_set_destroy(prefetch_set_t *set) {
    kh_destroy(prefetch, set);
}

int prefetch_set_add(prefetch_set_t *set, uint64_t page) {
    int ret;
    kh_put(prefetch, set, page, &ret);
    return ret >= 0;
}

int prefetch_set_contains(prefetch_set_t *set, uint64_t page) {
    return kh_get(prefetch, set, page) != kh_end(set);
}

int prefetch_set_remove(prefetch_set_t *set, uint64_t page) {
    khint_t k = kh_get(prefetch, set, page);
    if (k != kh_end(set)) {
        kh_del(prefetch, set, k);
        return 1;
    }
    return 0;
}
