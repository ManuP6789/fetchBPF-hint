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

SEC("tp/exceptions/page_fault_user")
int handle_fault(struct trace_event_raw_exceptions_page_fault_user* ctx) {
	struct event *e;
	u64 id;
	pid_t pid;
	u64 addr = ctx->address;
	u64 ip = ctx->ip;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_PAGEFAULT;                 
	e->pid = pid;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->address = addr;
	e->ip = ip;
	e->

	/* submit to userspace */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_sys_enter_mmap(struct syscall_enter_mmap_args *ctx)
{
	struct event *e;
	struct enter_key *key;
	pid_t pid;
	u32 tid;
    unsigned long addr = ctx->addr;
    unsigned long len  = ctx->len;
    unsigned long off  = ctx->off;
    unsigned long fd   = ctx->fd;
	u64 cgid = bpf_get_current_cgroup_id();
	u64 *allowed = bpf_map_lookup_elem(&target_cgroup, &(u32){0});

	if (!allowed)
		return 0;

	if (cgid != *allowed) 
		return 0;

	/* allocate key and event on stack */
	struct enter_key stack_key = {};
	struct event stack_event = {};
	key = &stack_key;
	e = &stack_event;

	pid = bpf_get_current_pid_tgid() >> 32;
	tid = (u32)bpf_get_current_pid_tgid();

	key->pid = pid;
	key->tid = tid;
	key->type = EVENT_MMAP;

	e->type = EVENT_MMAP;
	e->pid = pid;
	e->address = addr;
	e->cgroup_id = cgid;
	e->ip = 0; 
	e->new_len = len;
	e->fd = fd;
	e->offset = off;
	e->inode = 0;


	bpf_map_update_elem(&map_start, key, e, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tp_sys_exit_mmap(struct syscall_exit_mmap_args *ctx)
{
	struct event *e;
	struct enter_key key = {};
	pid_t pid;
	u32 tid;
    long ret = ctx->ret;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	tid = (u32)bpf_get_current_pid_tgid();

	key.pid = pid;
	key.tid = tid;
	key.type = EVENT_MMAP;

	/* if we recorded start of the process, calculate lifetime duration */
	e = bpf_map_lookup_elem(&map_start, &key);

	if (!e)
		return 0;

	bpf_map_delete_elem(&map_start, &key);
	if (ret < 0) {
		return 0;
	}

	u64 inode = 0;
	char path[256] = {};

	if (e->fd >= 0) {
		if (resolve_file_info(e->fd, &inode, path, sizeof(path)) == 0) {
			e->inode = inode;
			bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), path);
		}
	}

	/* reserve sample from BPF ringbuf */
	struct event *rb_e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!rb_e)
		return 0;

	__builtin_memcpy(rb_e, e, sizeof(*e));

	bpf_ringbuf_submit(rb_e, 0);
	return 0;
}

static __always_inline int resolve_file_info(int fd, u64 *inode_out, char* path_out, int path_len) {
	struct file *file;
	struct task_struct *task;
	struct fdtable *fdt;
	struct files_struct *files;
	struct path f_path;

	task = (struct task_struct *)bpf_get_current_task();
	files = BPF_CORE_READ(task, files);
	fdt = BPF_CORE_READ(files, fdt);

	// array of file
	file = BPF_CORE_READ(fdt, fd, fd);
	if(!file)
		return -1;
	
	*inode_out = BPF_CORE_READ(file, f_inode, i_ino);

	// obtain path
	f_path = BPF_CORE_READ(file, f_path);
	bpf_d_path(&f_path, path_out, path_len);

	return 0;
}
