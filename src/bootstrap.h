/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

extern long PAGE_SIZE;
#define MAX_FILENAME_LEN 127

#include <stdbool.h>

/* event.type:
 *  0 - mmap event 
 *  1 - mremap event
 *  2 - page-fault event
 *  3 - munmap event 
 */ 
#define EVENT_MMAP 0
#define EVENT_MREMAP 1
#define EVENT_PAGEFAULT 2
#define EVENT_MUNMAP 3

struct event {
	int type;
	int pid;
	unsigned long address;
	unsigned long old_address; 			// for mremap
	unsigned long new_len;     			// for mremap
	unsigned long ip;		   			// for pagefaultd
	unsigned long fd;
	// unsigned long offset;	   			// for mmap
    // unsigned long inode;	   			// for mmap
	// char filename[MAX_FILENAME_LEN];	// for mmap
};

struct enter_key {
    int pid;
    int tid;
    int type;    // 0=mmap, 1=mremap, 3=munmap
};

struct sys_enter_mmap_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int common_pid;

    int __syscall_nr;

    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

struct sys_enter_mremap_args {
	unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int common_pid;

    int __syscall_nr;

    unsigned long addr;
    unsigned long old_len;
    unsigned long new_len;
    unsigned long flags;
    unsigned long new_addr;
};

struct sys_enter_munmap_args {
	unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int common_pid;

    int __syscall_nr;

    unsigned long addr;
	unsigned long len;
};

struct sys_exit_mmap_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	long ret;
};

struct sys_exit_mremap_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	long ret;
};

struct sys_exit_munmap_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	long ret;
};


#endif /* __BOOTSTRAP_H */
