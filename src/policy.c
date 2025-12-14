// policies implemented
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ===============================
 * Sequential Prefetch Policy
 * =============================== */

int MAX_WINDOW = 32;
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

typedef struct {
    uint64_t last_fault_vaddr;
    uint64_t next_expected_vaddr;
    size_t window; 
} seq_ctx_t;


static policy_ctx_t *seq_init(void) {
    seq_ctx_t *ctx = calloc(1, sizeof(seq_ctx_t));
    ctx->last_fault_vaddr = UINT64_MAX;
    ctx->next_expected_vaddr = UINT64_MAX;
    ctx->window = 1;
    return (policy_ctx_t *)ctx;
}

static void seq_on_fault(policy_ctx_t *pctx, pid_t pid, uint64_t vaddr, 
                                                        uint64_t file_offset)
{
    seq_ctx_t *ctx = (seq_ctx_t *)pctx;
    
    uint64_t aligned_vaddr = vaddr & ~(PAGE_SIZE - 1);  // align to page boundary
    uint64_t fault_page = aligned_vaddr >> 12;
    printf("DEBUG: raw_vaddr=0x%lx, PAGE_SIZE=%lu, aligned=0x%lx, after_shift=0x%lx (%lu)\n", 
       vaddr, PAGE_SIZE, aligned_vaddr, fault_page, fault_page);

    if (ctx->last_fault_vaddr == UINT64_MAX) {
        ctx->window = 1;
        ctx->next_expected_vaddr = aligned_vaddr + (PAGE_SIZE);
        // printf("[SEQ] First fault: vaddr=0x%lx → window=1\n", aligned_vaddr);
    } else if (aligned_vaddr == ctx->next_expected_vaddr) {
        uint64_t last_page = ctx->last_fault_vaddr >> 12;
        int64_t actual_diff = (int64_t)fault_page - (int64_t)last_page;
        ctx->window = MIN(ctx->window * 2, MAX_WINDOW);
        printf("[SEQ] SEQUENTIAL fault: vaddr=0x%lx (page=%lu) last=0x%lx (page=%lu) actual_diff=%ld pages → window=%zu\n", 
               aligned_vaddr, fault_page, ctx->last_fault_vaddr, last_page, actual_diff, ctx->window);
        ctx->next_expected_vaddr = aligned_vaddr + (ctx->window * (PAGE_SIZE));
        ctx->next_expected_vaddr = aligned_vaddr + PAGE_SIZE;
    } else {
        ctx->window = 1;
        uint64_t expected_page = ctx->next_expected_vaddr >> 12;
        uint64_t last_page = ctx->last_fault_vaddr >> 12;
        int64_t expected_diff = (int64_t)expected_page - (int64_t)last_page;
        int64_t actual_diff = (int64_t)fault_page - (int64_t)last_page;
        printf("[SEQ] NON-SEQUENTIAL fault: vaddr=0x%lx (page=%lu) last=0x%lx (page=%lu) expected_diff=%ld actual_diff=%ld → reset window to 1\n",
               aligned_vaddr, fault_page, ctx->last_fault_vaddr, last_page, expected_diff, actual_diff);
        ctx->next_expected_vaddr = aligned_vaddr + (PAGE_SIZE);
    }

    ctx->last_fault_vaddr = aligned_vaddr;
}


static size_t seq_compute_prefetch(policy_ctx_t *pctx, uint64_t fault_vaddr, 
                                        uint64_t *out, size_t max) 
{
    seq_ctx_t *ctx = (seq_ctx_t*)pctx; 
    if (max == 0) return 0;

    uint64_t aligned_vaddr = fault_vaddr & ~(PAGE_SIZE - 1);
    uint64_t fault_page = aligned_vaddr >> 12;
    printf("DEBUG compute: raw_vaddr=0x%lx, PAGE_SIZE=%lu, after_shift=%lu\n", 
        fault_vaddr, PAGE_SIZE, fault_page);


    size_t count = 0;
    for (size_t i = 1; i <= ctx->window && count < max; i++) {
        out[count++] = aligned_vaddr + (i * PAGE_SIZE);
    }
    
    printf("[SEQ] compute_prefetch: window=%zu, prefetch_count=%zu\n", 
           ctx->window, count);
    return count;
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
    uint64_t last_fault_vaddr;
    int64_t stride;              // detected stride in pages
    int stride_confirmed;        // have we seen stride twice?
    size_t window;
    int fault_count;
} stride_ctx_t;

static policy_ctx_t *stride_init(void)
{
    stride_ctx_t *ctx = calloc(1, sizeof(stride_ctx_t));
    ctx->last_fault_vaddr = UINT64_MAX;
    ctx->stride = 0;
    ctx->stride_confirmed = 0;
    ctx->window = 1;
    ctx->fault_count = 0;
    return (policy_ctx_t *)ctx;
}

static void stride_on_fault(policy_ctx_t *pctx,
                            pid_t pid, uint64_t vaddr, uint64_t file_offset)
{
    stride_ctx_t *ctx = (stride_ctx_t *)pctx;
    uint64_t aligned_vaddr = vaddr & ~(PAGE_SIZE - 1);
    uint64_t fault_page = aligned_vaddr >> 12;
    
    ctx->fault_count++;

    if (ctx->last_fault_vaddr != UINT64_MAX) {
        uint64_t last_page = ctx->last_fault_vaddr >> 12;
        uint64_t current_page = aligned_vaddr >> 12;
        int64_t actual_stride = (int64_t)current_page - (int64_t)last_page;

        printf("[STRIDE DEBUG] Fault #%d: vaddr=0x%lx (page %lu), last_page=%lu, actual_stride=%ld\n",
               ctx->fault_count, aligned_vaddr, current_page, last_page, actual_stride);
    }

    if (ctx->last_fault_vaddr == UINT64_MAX) {
        // First fault
        ctx->window = 1;
        printf("[STRIDE] Fault #1: vaddr=0x%lx (page=%lu) → initializing\n", 
               aligned_vaddr, fault_page);
    } else {
        uint64_t last_page = ctx->last_fault_vaddr >> 12;
        int64_t detected_stride = (int64_t)fault_page - (int64_t)last_page;
        
        if (!ctx->stride_confirmed) {
            // Second fault - establish stride
            ctx->stride = detected_stride;
            ctx->stride_confirmed = 1;
            ctx->window = 1;
            printf("[STRIDE] Fault #2: stride=%ld detected, window=1\n", ctx->stride);
        } else if (detected_stride == ctx->stride) {
            // Stride confirmed again - grow window
            ctx->window = MIN(ctx->window * 2, MAX_WINDOW);
            printf("[STRIDE] Fault #%d: stride matches (stride=%ld) → window=%zu\n", 
                   ctx->fault_count, ctx->stride, ctx->window);
        } else {
            // Stride changed - reset
            ctx->stride = detected_stride;
            ctx->stride_confirmed = 1;
            ctx->window = 1;
            printf("[STRIDE] Fault #%d: stride changed! old=%ld new=%ld → reset window=1\n", 
                   ctx->fault_count, ctx->stride, detected_stride);
            ctx->stride = detected_stride;
        }
    }

    ctx->last_fault_vaddr = aligned_vaddr;
}

static size_t stride_compute(policy_ctx_t *pctx,
                             uint64_t fault_vaddr, uint64_t *out, size_t max)
{
    stride_ctx_t *ctx = (stride_ctx_t *)pctx;
    if (max == 0 || !ctx->stride_confirmed) 
        return 0;

    uint64_t aligned_vaddr = fault_vaddr & ~(PAGE_SIZE - 1);
    
    size_t count = 0;
    for (size_t i = 1; i <= ctx->window && count < max; i++) {
        int64_t target_page = ((int64_t)(aligned_vaddr >> 12)) + (i * ctx->stride);
        out[count++] = (uint64_t)target_page << 12;
    }
    
    printf("[STRIDE] compute_prefetch: stride=%ld, window=%zu, prefetch_count=%zu\n", 
           ctx->stride, ctx->window, count);
    return count;
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