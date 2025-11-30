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

#define QD	64
#define PAGEMAP_ENTRY 8
#define PAGE_PRESENT(v)   ((v >> 63) & 1)
#define PAGE_SWAPPED(v)   ((v >> 62) & 1)
#define PFN(v)            (v & ((1ULL << 55) - 1))
const int __endian_bit = 1;
#define is_bigendian() ( (*(char*)&__endian_bit) == 0 )
static int infd, outfd;
static khash_t(prefetch) *prefetching = NULL;
static const policy_t *policy = NULL;
static policy_ctx_t *policy_ctx = NULL;
struct io_uring ring;
long PAGE_SIZE = 0; 

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
	off_t first_offset, offset;
	size_t first_len;
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

/* ===============================
 * io_uring helpers
 * =============================== */
static int setup_context(unsigned entries, struct io_uring *ring)
{
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}

	return 0;
}

static void queue_prepped(struct io_uring *ring, struct io_data *data)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	assert(sqe);

	if (data->read)
		(sqe, infd, &data->iov, 1, data->offset);
	else
		io_uring_prep_writev(sqe, outfd, &data->iov, 1, data->offset);

	io_uring_sqe_set_data(sqe, data);
}

static int queue_read(struct io_uring *ring, off_t size, off_t offset){
	struct io_uring_sqe *sqe;
	struct io_data *data;

	data = malloc(size + sizeof(*data));
	if (!data)
		return 1;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		free(data);
		return 1;
	}

	data->read = 1;
	data->offset = data->first_offset = offset;

	data->iov.iov_base = data + 1;
	data->iov.iov_len = size;
	data->first_len = size;

	io_uring_prep_readv(sqe, infd, &data->iov, 1, offset);
	io_uring_sqe_set_data(sqe, data);
	return 0;
}

static void queue_write(struct io_uring *ring, struct io_data *data) {
	data->read = 0;
	data->offset = data->first_offset;

	data->iov.iov_base = data + 1;
	data->iov.iov_len = data->first_len;

	queue_prepped(ring, data);
	io_uring_submit(ring);
}

unsigned long get_physical_address(unsigned long pid, unsigned long vaddr) {
	printf("I am inside get physical...");
	char path[64];
	sprintf(path, "/proc/%ld/pagemap", pid);
	int fd = open(path, O_RDONLY);
	if(!fd){
      printf("Error! Cannot open pagemap %s\n", path);
      return -1;
   	}

	off_t off = (vaddr / PAGE_SIZE) * PAGEMAP_ENTRY;

    printf("Vaddr: 0x%lx, Page_size: %ld, Entry_size: %d\n", vaddr, PAGE_SIZE, PAGEMAP_ENTRY);
	printf("Reading %s at 0x%llx\n", path, (unsigned long long) off);

	if(lseek(fd, off, SEEK_SET) == -1){
      perror("Failed to do fseek!");
	  close(fd);
      return -1;
    }
	
	uint64_t entry = 0;
	ssize_t n = read(fd, &entry, PAGEMAP_ENTRY);
    close(fd);

	if (n != PAGEMAP_ENTRY) {
        fprintf(stderr, "Short read from pagemap\n");
        return 0;
    }

	printf("Pagemap entry = 0x%016llx\n", (unsigned long long)entry);

	if (!PAGE_PRESENT(entry)) {
        printf("Page not present\n");
        return 0;
    }
    
	uint64_t pfn = PFN(entry);
    printf("PFN = 0x%llx\n", (unsigned long long)pfn);

	printf("PFN = 0x%llx\n", (unsigned long long)pfn);

    uint64_t phys = (pfn * getpagesize()) + (vaddr % getpagesize());
    printf("Physical address = 0x%llx\n", (unsigned long long)phys);

    return phys;
}

static int handle_fault(struct event *e) {
	printf("%-5s %-7d %lx address=0x%lx ip=0x%lx\n",
			"FAULT", e->pid, e->cgroup_id, e->address, e->ip);

	
	uint64_t vaddr = e->address;
	uint64_t page = vaddr >> 12;
	
	// Check if the page is already in the prefetch set
	if (prefetch_set_contains(prefetching, page)) {
		return 1;
	} 

	// Call prefetcher to get page addresses to prefetch with io_uring
	uint64_t targets[32];   // max prefetch count
	size_t n = policy->compute_prefetch(policy_ctx, vaddr, targets, 32);

	for (size_t i = 0; i < n; i++) {
		uint64_t target_page = targets[i] >> 12;
		if (prefetch_set_contains(prefetching, target_page))
			continue;
		
		// submit_prefetch(&ring, targets[i]);  // you implement this
		prefetch_set_add(prefetching, target_page);            // track outstanding reads
	}

	
	
	// submit prefetch
	// Read prefetches and remove from set  
	return 0;
} 

static int handle_mmap(struct event *e) {
	printf("%-5s %-7d %lx address=0x%lx ip=0x%lx\n",
			"MMAP", e->pid, e->cgroup_id, e->address, e->ip, );
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	switch (e->type) {
		case EVENT_PAGEFAULT: handle_fault(e); break;
		case EVENT_MMAP:	  handle_mmap(e); break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	struct io_uring ring;
	struct maps_cache_t *maps_c;
	policy = policy_sequential();       // or stride(), none(), etc.
    policy_ctx = policy->init(); 
	prefetch_set_t *prefetching = prefetch_set_create();
	int err;

	maps_c = maps_load_from_pid(2088);


	uint64_t cg_id = get_cgroup_id("/sys/fs/cgroup/prefetch");
    printf("Cgroup ID: %lu\n", cg_id);

	if (!policy_ctx) {
        fprintf(stderr, "Failed to initialize policy\n");
        return 1;
    }

	if (!prefetching) {
        fprintf(stderr, "Failed to create prefetch set\n");
        return 1;
    }

	/* Set up io_uring*/
	if (setup_context(QD, &ring))
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
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

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
