// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct enter_key);
	__type(value, struct event);
} map_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

struct trace_event_raw_exceptions_page_fault_user {
	struct trace_entry ent;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/exceptions/page_fault_user")
int handle_fault(struct trace_event_raw_exceptions_page_fault_user* ctx) {
	struct event *e;
	u64 id;
	pid_t pid;
	u64 addr = ctx->address;
	u64 ip = ctx->ip;
	u64 cgid = bpf_get_current_cgroup_id();
    u64 *allowed = bpf_map_lookup_elem(&target_cgroup, &(u32){0});

    if (!allowed || cgid != *allowed)
        return 0;
	
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;

	// reserve sample from BPF ringbuf 
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u64 maj = BPF_CORE_READ(task, maj_flt);
	u64 min = BPF_CORE_READ(task, min_flt);

	e->type = EVENT_PAGEFAULT;                 
	e->pid = pid;
	e->address = addr;
	e->ip = ip;
	e->maj = maj;
	e->min = min;

	// submit to userspace 
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int handle_sys_enter_common(u32 type, u64 addr, u64 len,
    											   			   		    u64 fd)
{
    u64 cgid = bpf_get_current_cgroup_id();
    u64 *allowed = bpf_map_lookup_elem(&target_cgroup, &(u32){0});

    if (!allowed || cgid != *allowed)
        return 0;

    struct enter_key key = {};
    struct event e = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    key.type = type;

    e.type     = type;
    e.pid      = key.pid;
    e.address  = addr;
    e.new_len  = len;
    e.fd       = fd;
    e.ip       = 0;       

    bpf_map_update_elem(&map_start, &key, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_sys_enter_mmap(struct sys_enter_mmap_args *ctx)
{
	return handle_sys_enter_common(EVENT_MMAP, ctx->addr, ctx->len, ctx->fd);
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int tp_sys_enter_mremap(struct sys_enter_mremap_args *ctx)
{
	return handle_sys_enter_common(EVENT_MREMAP,ctx->addr, ctx->new_len, 0);
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tp_sys_enter_munmap(struct sys_enter_munmap_args *ctx)
{
	return handle_sys_enter_common(EVENT_MUNMAP, ctx->addr, ctx->len, 0);
}

static __always_inline int handle_sys_exit_common(u32 type, long ret)
{
    struct enter_key key = {};
    struct event *e;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    key.pid = pid;
    key.tid = tid;
    key.type = type;

    e = bpf_map_lookup_elem(&map_start, &key);
    if (!e)
        return 0;

    bpf_map_delete_elem(&map_start, &key);

    // if syscall failed dont emit event 
    if (ret < 0)
        return 0;

    // push event to ring buffer 
    struct event *rb_e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!rb_e)
        return 0;

    __builtin_memcpy(rb_e, e, sizeof(*e));
    bpf_ringbuf_submit(rb_e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_mmap")
int tp_sys_exit_mmap(struct sys_exit_mmap_args *ctx)
{
	return handle_sys_exit_common(EVENT_MMAP, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_mremap")
int tp_sys_exit_mremap(struct sys_exit_mremap_args *ctx)
{
	return handle_sys_exit_common(EVENT_MREMAP, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int tp_sys_exit_munmap(struct sys_exit_munmap_args *ctx)
{
	return handle_sys_exit_common(EVENT_MUNMAP, ctx->ret);
}
