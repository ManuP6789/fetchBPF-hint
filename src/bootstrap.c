// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include "bootstrap.h"
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/resource.h>
#include "liburing.h"
#include <assert.h>
#include "prefetch_set.h"
#include <bpf/libbpf.h>
#include "bootstrap.skel.h"
#include "policy.h"
#include "maps.h"
#include <sys/time.h>

#define QD	256
static khash_t(prefetch) *prefetching = NULL;
static const policy_t *policy = NULL;
static policy_ctx_t *policy_ctx = NULL;
struct maps_cache_t *maps_c = NULL;
struct io_uring ring;
long PAGE_SIZE = 0; 
const int SUBMIT_BATCH = 32; 
uint64_t last_submit_tsc;
int pending_submits = 0;  
const uint64_t SUBMIT_EVERY_NS = 1000000;  // 0.5 ms
unsigned long major_fault_counter = 0;
static unsigned long long total_fault_latency_ns = 0;
static unsigned long fault_latency_samples = 0;

// Instrumentation metrics 
unsigned long total_prefetches = 0;
unsigned long used_prefetches = 0;
unsigned long avoided_faults = 0;
unsigned long total_major_faults = 0;
unsigned long total_pages_to_readahead = 0;

__attribute__((constructor))
static void init_page_size(void) {
    PAGE_SIZE = getpagesize();
}

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

struct io_data {
	int read;
	int fd;
	off_t offset;
	size_t len;
	unsigned long page;
	struct iovec iov;
};

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static inline __u64 get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

uint64_t get_cgroup_id(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat");
        return 0;
    }
    return st.st_ino;  // the kernel uses the inode as the cgroup ID
}

pid_t get_single_pid_in_cgroup(const char *cgpath) {
    char procs_path[512];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgpath);

    FILE *f = fopen(procs_path, "r");
    if (!f) {
        return -1; 
    }

    long first_pid = -1;
    long second_pid = -1;

    if (fscanf(f, "%ld", &first_pid) != 1) {
        fclose(f);
        errno = ESRCH;   // "no such process"
        return -1;
    }

    // Check if there's a second PID
    if (fscanf(f, "%ld", &second_pid) == 1) {
        fclose(f);
        errno = EBUSY;   // "resource busy" (too many processes)
        return -1;
    }

    fclose(f);
    return (pid_t)first_pid;
}

int wait_for_pid_in_cgroup(const char *cgpath)
{
    const int step_ms = 100;    // poll every 100ms
    int waited = 0;

    while (1) {
        int pid = get_single_pid_in_cgroup(cgpath);
        if (pid > 0) {
            return pid;  // found it!
        }

        usleep(step_ms * 1000);
        waited += step_ms;
    }
}

/* ===============================
 * io_uring helpers
 * =============================== */
static int setup_context()
{
	int ret;

	ret = io_uring_queue_init(QD, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}

	return 0;
}

// Call periodically or after batch of submits to collect completions
static void reap_cqes() {
	// fprintf(stderr, "hey crashing here in reap lol\n");
    struct io_uring_cqe *cqe;
    while (io_uring_peek_cqe(&ring, &cqe) == 0) {
        struct io_data *d = io_uring_cqe_get_data(cqe);
        int res = cqe->res; // result: bytes read or negative errno
        uint64_t page_idx = 0;
        if (d) {
			prefetch_set_remove(prefetching, d->page);
        }

        if (res < 0) {
            // read failed. log errno = -res
            fprintf(stderr, "prefetch read failed: %s\n", strerror(-res));
        } 

        if (d) {
            free(d);
        }

        io_uring_cqe_seen(&ring, cqe);
    }
	// fprintf(stderr, "lol nvm not in reap\n");
}


static int open_fd_for_region(const map_region_t *reg) {
    if (!reg->file_backed || reg->pathname[0] == '\0') return -1;
    int fd = open(reg->pathname, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        // Non-fatal: file may have been unlinked by the process
        return -1;
    }
    return fd;
}

static int submit_prefetch(uint64_t vaddr) {
	struct io_uring_sqe *sqe = NULL;
    struct io_data *data = NULL;
    map_region_t *region;
	off_t file_offset;
	off_t page_aligned_off;
	int fd = -1;
	uint64_t page_idx = vaddr >> 12;

	// find region for vaddr
	region = maps_lookup(maps_c, vaddr);

	if (!region->file_backed) {
		// nothing to read, anonymous map
		return -1;
	}
    
	// compute file offset: (vaddr - region.start) + region.offset
	if (vaddr < region->start || vaddr >= region->end) {
		// out of region
		return -1;
	}
	file_offset = (off_t)((vaddr - region->start) + region->offset);

	// align offset to page boundary
	page_aligned_off = file_offset & ~(off_t)(PAGE_SIZE - 1);

	// check if fd already in map_region, otherwise open file
	if (region->fd > -1) {
		fd = region->fd;
	} else {
		fd = open_fd_for_region(region);
		if (fd < 0)
			return -1;
		region->fd = fd;
	}

    data = malloc(PAGE_SIZE + sizeof(*data));
    if (!data) 
		return -1;

	memset(data, 0, sizeof(*data));
	data->fd = fd;
	data->read = 1;
    data->offset = page_aligned_off;
	data->len = PAGE_SIZE;
	data->page = page_idx;
	data->iov.iov_base = (void*)(data + 1); // buffer directly after struct
	data->iov.iov_len = PAGE_SIZE;

	// check in-flight set and add BEFORE submitting to avoid races
    if (prefetch_set_contains(prefetching, page_idx)) {
        // already requested
        free(data);
        return -1;
    }
    prefetch_set_add(prefetching, page_idx);
    
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
		prefetch_set_remove(prefetching, page_idx);
        free(data);
        return -1;
    }
    
    io_uring_prep_readv(sqe, fd, &data->iov, 1, data->offset);

    io_uring_sqe_set_data(sqe, data);
	pending_submits++;

	total_prefetches++;
    
    return 0;
}

static inline void maybe_submit() {
    uint64_t now = get_time_ns();   // clock_gettime(CLOCK_MONOTONIC, ...)
    if (pending_submits >= SUBMIT_BATCH ||
        now - last_submit_tsc >= SUBMIT_EVERY_NS) {

		printf("number of submits and time: %i, %lu\n", pending_submits, now - last_submit_tsc);
        io_uring_submit(&ring);
		// fprintf(stderr, "After io_uring submit\n");
        last_submit_tsc = now;
        pending_submits = 0;
    }
}

static int handle_fault(const struct event *e) {
	uint64_t t0 = get_time_ns();
	// fprintf(stderr, "inside handle fault lol\n");
	// printf("%-5s %-7d address=0x%lx ip=0x%lx hello wtf\n",
	// 		"FAULT", e->pid, e->address, e->ip);
	// printf("this is major fault from bpf %lu and this is from major_fault_counter %lu, this is min_fault %lu\n",
	// 										e->maj, major_fault_counter, e->min);
	if (e->maj == major_fault_counter) {
		return 1;
	}
	total_major_faults++;
	major_fault_counter = e->maj;

	uint64_t vaddr = e->address;
	uint64_t page = vaddr >> 12;
	
	// Check if the page is already in the prefetch set
	if (prefetch_set_contains(prefetching, page)) {
		avoided_faults++;
		return 1;
	}
	policy->on_page_fault(policy_ctx, e->pid, vaddr, 0);

	// Call prefetcher to get page addresses to prefetch with io_uring
	uint64_t targets[64];   // max prefetch count
	size_t n = policy->compute_prefetch(policy_ctx, vaddr, targets, 64);
	total_pages_to_readahead += n;
	for (size_t i = 0; i < n; i++) {
		if (submit_prefetch(targets[i]))
			fprintf(stderr, "Failed to submit prefetch at addr %lx\n", targets[i]);
	}

	uint64_t t1 = get_time_ns();   // END TIMING

    // accumulate
    total_fault_latency_ns += (t1 - t0);
	fault_latency_samples++;

	return 0;
} 

static int handle_mmap(const struct event *e) {
	printf("%-5s %-7d address=0x%lx ip=0x%lx\n",
			"MMAP", e->pid, e->address, e->ip);
	if (maps_reload(maps_c))
		fprintf(stderr, "Failed to reload maps cache\n");
	return 0;
}

static int handle_mremap(const struct event *e) {
	printf("%-5s %-7d address=0x%lx ip=0x%lx\n",
			"MREMAP", e->pid, e->address, e->ip);
	if (maps_reload(maps_c))
		fprintf(stderr, "Failed to reload maps cache\n");
	return 0;
}

static int handle_munmap(const struct event *e) {
	printf("%-5s %-7d address=0x%lx ip=0x%lx\n",
			"MUNMAP", e->pid, e->address, e->ip);
	if (maps_reload(maps_c))
		fprintf(stderr, "Failed to reload maps cache\n");
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// fprintf(stderr, "yo crashing here in handle_event\n");
	const struct event *e = data;

	switch (e->type) {
		case EVENT_PAGEFAULT: handle_fault(e); break;
		case EVENT_MMAP:	  handle_mmap(e); break;
		case EVENT_MREMAP:	  handle_mremap(e); break;
		case EVENT_MUNMAP:	  handle_munmap(e); break;
	}
	// fprintf(stderr, "lol jk not in handle event\n");

	return 0;
}

int main(int argc, char **argv) {
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	struct io_uring ring;
	policy = policy_sequential();   
	// policy = policy_stride();
    policy_ctx = policy->init(); 
	prefetch_set_t *prefetching = prefetch_set_create();
	int err;

	uint64_t cg_id = get_cgroup_id("/sys/fs/cgroup/prefetch");
    printf("Cgroup ID: %lu\n", cg_id);

	int target_pid = wait_for_pid_in_cgroup("/sys/fs/cgroup/prefetch");

	printf("Found process in cgroup: PID=%d\n", target_pid);
	maps_c = maps_load_from_pid(target_pid);

	if (!policy_ctx) {
        fprintf(stderr, "Failed to initialize policy\n");
        return 1;
    }

	if (!prefetching) {
        fprintf(stderr, "Failed to create prefetch set\n");
        return 1;
    }

	/* Set up io_uring*/
	if (setup_context())
		return 1;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	int map_fd = bpf_map__fd(skel->maps.target_cgroup);
	if (map_fd < 0) {
		fprintf(stderr, "could not find target_cgroup map\n");
		return 1;
	}

	uint32_t key = 0;
    err = bpf_map_update_elem(map_fd, &key, &cg_id, BPF_ANY);
    if (err < 0) {
        perror("update cgroup map");
        return 1;  
    }

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		// fprintf(stderr, "crashing here before ringbuffer handling\n");
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// fprintf(stderr, "not crash after ringbuffer handling\n");
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}

		maybe_submit();

		reap_cqes();
	}
	printf("=== Prefetch Stats ===\n");
	printf("Total prefetches: %lu\n", total_prefetches);
	printf("Used prefetches: %lu\n", used_prefetches);
	printf("Prefetch accuracy: %.2f %%\n",
		100.0 * used_prefetches / total_prefetches);

	printf("Major faults: %lu\n", total_major_faults);
	printf("Avoided faults: %lu\n", avoided_faults);
	printf("Total readahead pages: %lu\n", total_pages_to_readahead);
	printf("Prefetch coverage: %.2f %%\n",
		100.0 * avoided_faults / total_major_faults);
	printf("Avg fault→prefetch latency: %.2f µs\n",
       (double)total_fault_latency_ns / fault_latency_samples / 1000.0);

cleanup:
	/* Clean up */
	io_uring_queue_exit(&ring);
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);
	prefetch_set_destroy(prefetching);
	maps_free(maps_c);
	policy->destroy(policy_ctx);
	return err < 0 ? -err : 0;
}
