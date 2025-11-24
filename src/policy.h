#ifndef __POLICY_H
#define __POLICY_H

#include <stdint.h>
#include <stddef.h>
#include "bootstrap.h"

typedef struct policy_ctx policy_ctx_t;

typedef struct policy {
    // Called once to initialize the policy context.
    policy_ctx_t *(*init)(void);

    // Called to process a page fault event.
    // pid, vaddr, and file offset (if known) can be passed in.
    void (*on_page_fault)(policy_ctx_t *ctx, pid_t pid, uint64_t vaddr,
                                                uint64_t file_offset);

    // Called to compute what addresses should be prefetched.
    // Returns number of entries placed in out_addrs[].
    size_t (*compute_prefetch)(policy_ctx_t *ctx, uint64_t faulting_vaddr,
                               uint64_t *out_addrs, size_t max_addrs);

    // Cleanup function.
    void (*destroy)(policy_ctx_t *ctx);

} policy_t;

const policy_t *policy_sequential(void);
const policy_t *policy_stride(void);
const policy_t *policy_none(void);

#endif 