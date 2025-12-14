#include "prefetch_set.h"

prefetch_set_t *prefetch_set_create(void) {
    return kh_init(prefetch);
}

void prefetch_set_destroy(prefetch_set_t *set) {
    if (!set) return;
    kh_destroy(prefetch, set);
}

/* ret > 0 == inserted, ret == 0 == already present */
int prefetch_set_add(prefetch_set_t *set, uint64_t page) {
    if (!set) {
        return 0;
    }
    int ret;
    kh_put(prefetch, set, page, &ret);
    return ret >= 0;
}

int prefetch_set_contains(prefetch_set_t *set, uint64_t page) {
    if (!set) return 0;
    khiter_t k = kh_get(prefetch, set, page);
    return (k != kh_end(set));
}

int prefetch_set_remove(prefetch_set_t *set, uint64_t page) {
    if (!set) return 0;
    khint_t k = kh_get(prefetch, set, page);
    if (k != kh_end(set)) {
        kh_del(prefetch, set, k);
        return 1;
    }
    return 0;
}
