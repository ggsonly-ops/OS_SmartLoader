#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <inttypes.h>

static size_t PAGE_SIZE = 0;
static int elf_fd = -1;
static Elf32_Ehdr ehdr;
static Elf32_Phdr *phdrs = NULL;
static int phnum = 0;

/* Counters */
static volatile unsigned long page_faults = 0;
static volatile unsigned long page_allocs = 0;

/* Segment info for PT_LOAD segments */
typedef struct {
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    unsigned long pages_allocated;
} seginfo_t;

static seginfo_t *segments = NULL;
static int seg_count = 0;

/* Track mapped pages to avoid double counting allocations */
typedef struct {
    void *page_addr;
    int seg_idx;
} mapped_page_t;

static mapped_page_t *mapped_pages = NULL;
static size_t mapped_pages_capacity = 0;
static size_t mapped_pages_count = 0;

/* ---------------- Error helper functions ---------------- */

static void fatal_perror(const char *ctx) {
    perror(ctx);
    exit(1);
}

static void fatal_msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}


static void add_mapped_page(void *page_addr, int seg_idx) {
    if (mapped_pages_count == mapped_pages_capacity) {
        mapped_pages_capacity = (mapped_pages_capacity == 0) ? 256 : mapped_pages_capacity * 2;
        mapped_pages = realloc(mapped_pages, mapped_pages_capacity * sizeof(mapped_page_t));
        if (!mapped_pages) {
            perror("realloc mapped_pages");
            _exit(1);
        }
    }
    mapped_pages[mapped_pages_count].page_addr = page_addr;
    mapped_pages[mapped_pages_count].seg_idx = seg_idx;
    mapped_pages_count++;
}

static int find_mapped_page(void *page_addr) {
    for (size_t i = 0; i < mapped_pages_count; ++i) {
        if (mapped_pages[i].page_addr == page_addr) return mapped_pages[i].seg_idx;
    }
    return -1;
}