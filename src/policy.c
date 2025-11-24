// policies implemented
#include "policy.h"
#include <stdlib.h>
#include <string.h>

/* ===============================
 * Sequential Prefetch Policy
 * =============================== */

long PAGE_SIZE;
int MAX_WINDOW = 8;
typedef struct {
    uint64_t last_fault;
    uint64_t next_expected_page;
    size_t window; 
} seq_ctx_t;

static policy_ctx_t *seq_init(void) {
    seq_ctx_t *ctx = calloc(1, sizeof(seq_ctx_t));
    ctx->last_fault = UINT64_MAX;
    ctx->next_expected_page = UINT64_MAX;
    ctx->window = 1;
    return (policy_ctx_t *)ctx;
}

static void seq_on_fault(policy_ctx_t *pctx, pid_t pid, uint64_t vaddr, 
                                                        uint64_t file_offset)
{
    seq_ctx_t *ctx = (seq_ctx_t *)pctx;
    uint64_t page = vaddr & ~(PAGE_SIZE - 1);

    if (ctx->last_fault == UINT64_MAX) {
        ctx->window = 1;
    } else if (page == ctx->next_expected_page) {
        // sequential
        ctx->window = MIN(ctx->window * 2, MAX_WINDOW);
    } else {
        // jump or random
        ctx->window = 1;
    }

    ctx->last_fault = page;
    ctx->next_expected_page = page + ((ctx->window + 1) * PAGE_SIZE);
}

static size_t seq_compute_prefetch(policy_ctx_t *pctx, uint64_t fault, 
                                        uint64_t *out, size_t max) 
{
    seq_ctx_t *ctx = (seq_ctx_t*)pctx; 
    if (max == 0) return 0;

    uint64_t page = fault & ~(PAGE_SIZE - 1);

    for (int i = 1; i <= ctx->window && i <= max; i++)
        out[i-1] = page + (i * PAGE_SIZE);

    return ctx->window;
}

static void seq_destroy(policy_ctx_t *pctx) {
    free(pctx);
}

static const policy_t SEQUENTIAL_POLICY = {
    .init = seq_init,
    .on_page_fault = seq_on_fault,
    .compute_prefetch = seq_compute_prefetch,
    .destroy = seq_destroy
};

const policy_t *policy_sequential(void) {
    return &SEQUENTIAL_POLICY;
}


/* ===============================
 * Stride Prefetch Policy
 * =============================== */

typedef struct {
    uint64_t stride;
} stride_ctx_t;

static policy_ctx_t *stride_init(void)
{
    stride_ctx_t *ctx = calloc(1, sizeof(stride_ctx_t));
    ctx->stride = 4096;
    return (policy_ctx_t *)ctx;
}

static void stride_on_fault(policy_ctx_t *ctx,
                            pid_t pid, uint64_t vaddr, uint64_t file_offset)
{
    /* no-op */
}

static size_t stride_compute(policy_ctx_t *pctx,
                             uint64_t fault, uint64_t *out, size_t max)
{
    stride_ctx_t *ctx = (stride_ctx_t *)pctx;
    if (max == 0) return 0;
    out[0] = fault + ctx->stride;
    return 1;
}

static void stride_destroy(policy_ctx_t *ctx)
{
    free(ctx);
}

static const policy_t STRIDE_POLICY = {
    .init = stride_init,
    .on_page_fault = stride_on_fault,
    .compute_prefetch = stride_compute,
    .destroy = stride_destroy
};

const policy_t *policy_stride(void)
{
    return &STRIDE_POLICY;
}


/* ===============================
 * No Prefetch Policy
 * =============================== */

static policy_ctx_t *none_init(void)
{
    return NULL;
}

static void none_on_fault(policy_ctx_t *ctx,
                          pid_t pid, uint64_t vaddr, uint64_t file_offset)
{
    /* do nothing */
}

static size_t none_compute(policy_ctx_t *ctx,
                           uint64_t fault, uint64_t *out, size_t max)
{
    return 0;
}

static void none_destroy(policy_ctx_t *ctx)
{
    /* nothing */
}

static const policy_t NONE_POLICY = {
    .init = none_init,
    .on_page_fault = none_on_fault,
    .compute_prefetch = none_compute,
    .destroy = none_destroy
};

const policy_t *policy_none(void)
{
    return &NONE_POLICY;
}