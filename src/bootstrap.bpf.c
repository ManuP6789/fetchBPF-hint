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
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct trace_event_raw_exceptions_page_fault_user {
	struct trace_entry ent;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};
// name: page_fault_user
// ID: 119
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:unsigned long address;    offset:8;       size:8; signed:0;
//         field:unsigned long ip; offset:16;      size:8; signed:0;
//         field:unsigned long error_code; offset:24;      size:8; signed:0;

// print fmt: "address=%ps ip=%ps error_code=0x%lx", (void *)REC->address, (void *)REC->ip, REC->error_code

// struct trace_event_raw_sched_process_exec {
//         struct trace_entry ent;
//         u32 __data_loc_filename;
//         pid_t pid;
//         pid_t old_pid;
//         char __data[0];
// };
// name: sched_process_exec
// ID: 311
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:__data_loc char[] filename;       offset:8;       size:4; signed:1;
//         field:pid_t pid;        offset:12;      size:4; signed:1;
//         field:pid_t old_pid;    offset:16;      size:4; signed:1;

// print fmt: "filename=%s pid=%d old_pid=%d", __get_str(filename), REC->pid, REC->old_pid
const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;  
	u64 id, ts, *start_ts, duration_ns = 0;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}


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

	/* fill out the sample with data */
	e->type = 2;                  /* 2 == page-fault event */
	e->pid = pid;
	e->ppid = 0;                  /* not populated here */
	e->exit_event = false;
	e->duration_ns = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	e->address = addr;
	e->ip = ip;

	/* submit to userspace */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
