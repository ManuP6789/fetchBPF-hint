/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
extern long PAGE_SIZE;

#include <stdbool.h>


/* event.type:
 *  0 - exec/exit event (original)
 *  1 - exec event (kept for readability; we use exit_event flag for exit)
 *  2 - page-fault event
 */
struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;

	/* simple tag to distinguish event types */
	int type;

	/* page-fault fields (valid when type == 2) */
	unsigned long address;
	unsigned long ip;
	unsigned long cgroup_id;
};

#endif /* __BOOTSTRAP_H */
