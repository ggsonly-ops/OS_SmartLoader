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

/* Find the loadable segment index that contains the given address (virtual) */
static int find_segment_for_addr(uint32_t addr) {
    for (int i = 0; i < seg_count; ++i) {
        uint32_t start = segments[i].p_vaddr;
        uint32_t end = segments[i].p_vaddr + segments[i].p_memsz;
        if (addr >= start && addr < end) return i;
    }
    return -1;
}

/* Convert ELF p_flags to mprotect flags */
static int elf_flags_to_prot(uint32_t flags) {
    int prot = 0;
    if (flags & PF_R) prot |= PROT_READ;
    if (flags & PF_W) prot |= PROT_WRITE;
    if (flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

/* SIGSEGV handler with correct overlap math */
static void segv_handler(int sig, siginfo_t *si, void *unused) {
    (void)sig; (void)unused;
    ++page_faults;

    void *fault_addr_void = si->si_addr;
    uintptr_t fault_addr = (uintptr_t)fault_addr_void;
    uintptr_t page_start = fault_addr & ~(PAGE_SIZE - 1);
    uintptr_t page_end = page_start + PAGE_SIZE;

    int seg_idx = find_segment_for_addr((uint32_t)fault_addr);
    if (seg_idx < 0) {
        fprintf(stderr, "Segfault at %p is outside any PT_LOAD segment. Exiting.\n", fault_addr_void);
        _exit(1);
    }

    if (find_mapped_page((void*)page_start) != -1) {
        fprintf(stderr, "Protection fault at %p on already-mapped page. Exiting.\n", fault_addr_void);
        _exit(1);
    }

    /* Map the page (temporary RWX to copy) */
    void *m = mmap((void*)page_start, PAGE_SIZE,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (m == MAP_FAILED) {
        perror("mmap in handler");
        _exit(1);
    }

    ++page_allocs;
    segments[seg_idx].pages_allocated += 1;
    add_mapped_page((void*)page_start, seg_idx);

    /* Correct overlap calculation:*/
    uintptr_t seg_vstart = (uintptr_t)segments[seg_idx].p_vaddr;
    uintptr_t seg_vfile_end = seg_vstart + (uintptr_t)segments[seg_idx].p_filesz;

    uintptr_t overlap_start = (page_start > seg_vstart) ? page_start : seg_vstart;
    uintptr_t overlap_end = (page_end < seg_vfile_end) ? page_end : seg_vfile_end;

    size_t bytes_from_file = 0;
    off_t file_offset = 0;
    size_t write_offset_in_page = 0;

    if (overlap_end > overlap_start) {
        bytes_from_file = overlap_end - overlap_start;
        file_offset = (off_t)segments[seg_idx].p_offset + (off_t)(overlap_start - seg_vstart);
        write_offset_in_page = overlap_start - page_start;
    } else {
        bytes_from_file = 0;
        write_offset_in_page = 0;
    }
    /* Read file bytes into the appropriate offset within the page */
    if (bytes_from_file > 0) {
        ssize_t rr = pread(elf_fd, (void*)((uintptr_t)page_start + write_offset_in_page), bytes_from_file, file_offset);
        if (rr < 0) {
            perror("pread in handler");
            _exit(1);
        }
        if ((size_t)rr + write_offset_in_page < PAGE_SIZE) {
            memset((void*)(page_start + (size_t)rr + write_offset_in_page), 0, PAGE_SIZE - (size_t)rr - write_offset_in_page);
        }
    } else {
        memset((void*)page_start, 0, PAGE_SIZE);
    }

    int prot = elf_flags_to_prot(segments[seg_idx].p_flags);
    if (mprotect((void*)page_start, PAGE_SIZE, prot) != 0) {
        perror("mprotect in handler");
        _exit(1);
    }
}

/* Read ELF headers and populate segments[] for PT_LOAD entries */
static void load_elf_headers(const char *path) {
    if (elf_fd < 0) {
        elf_fd = open(path, O_RDONLY);
        if (elf_fd < 0) {
            fatal_perror("open ELF");
        }
    }
    if (pread(elf_fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        fatal_perror("read elf header");
    }
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        fatal_msg("Not an ELF file");
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
        fatal_msg("Only ELF32 supported");
    }

    phnum = ehdr.e_phnum;
    if (phnum <= 0) {
        fatal_msg("No program headers");
    }

    phdrs = malloc(phnum * sizeof(Elf32_Phdr));
    if (!phdrs) { fatal_perror("malloc phdrs"); }
    off_t ph_off = ehdr.e_phoff;
    ssize_t want = phnum * sizeof(Elf32_Phdr);
    ssize_t rr = pread(elf_fd, phdrs, want, ph_off);
    if (rr != want) { fatal_perror("pread phdrs"); }

    seg_count = 0;
    for (int i = 0; i < phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) seg_count++;
    }
    segments = calloc(seg_count, sizeof(seginfo_t));
    if (!segments) { fatal_perror("calloc segments"); }
    int si = 0;
    for (int i = 0; i < phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        segments[si].p_offset = phdrs[i].p_offset;
        segments[si].p_vaddr  = phdrs[i].p_vaddr;
        segments[si].p_filesz = phdrs[i].p_filesz;
        segments[si].p_memsz  = phdrs[i].p_memsz;
        segments[si].p_flags  = phdrs[i].p_flags;
        segments[si].pages_allocated = 0;
        si++;
    }
}
/* Compute internal fragmentation bytes */
static unsigned long compute_internal_frag_bytes(void) {
    unsigned long total = 0;
    for (int i = 0; i < seg_count; ++i) {
        unsigned long alloc_bytes = segments[i].pages_allocated * PAGE_SIZE;
        if (alloc_bytes > segments[i].p_memsz) total += (alloc_bytes - segments[i].p_memsz);
    }
    return total;
}


/* Close ELF fd if open */
static void close_elf_fd(void) {
    if (elf_fd >= 0) {
        close(elf_fd);
        elf_fd = -1;
    }
}

/* Free program headers */
static void free_phdrs(void) {
    if (phdrs) {
        free(phdrs);
        phdrs = NULL;
        phnum = 0;
    }
}

/* Free segment info */
static void free_segments(void) {
    if (segments) {
        free(segments);
        segments = NULL;
        seg_count = 0;
    }
}

/* Free mapped_pages array and reset its counters (does NOT unmap pages) */
static void free_mapped_pages(void) {
    if (mapped_pages) {
        free(mapped_pages);
        mapped_pages = NULL;
    }
    mapped_pages_capacity = 0;
    mapped_pages_count = 0;
}

/* Unmap all mapped pages recorded in mapped_pages[]. */
static void unmap_mapped_pages(void) {
    for (size_t i = 0; i < mapped_pages_count; ++i) {
        void *addr = mapped_pages[i].page_addr;
        if (addr != NULL) {
            /* PAGE_SIZE is global; assume it's set. */
            if (munmap(addr, PAGE_SIZE) != 0) {
                /* best-effort: use perror in normal flow only */
                perror("munmap in unmap_mapped_pages");
            }
        }
    }
}

/* Reset counters and any runtime state (does not free memory) */
static void reset_state(void) {
    page_faults = 0;
    page_allocs = 0;
    PAGE_SIZE = (PAGE_SIZE == 0) ? sysconf(_SC_PAGESIZE) : PAGE_SIZE;
}

/* Print stats summary (same format you used in main) */
static void report_stats(void) {
    unsigned long frag_bytes = compute_internal_frag_bytes();
    double frag_kb = ((double)frag_bytes) / 1024.0;
    unsigned long rounded_kb = (frag_bytes + 1023) / 1024;

    printf("Page faults: %lu\n", page_faults);
    printf("Page allocations: %lu\n", page_allocs);
    printf("Internal fragmentation: %.2fKB (%lu bytes) [rounded KB: %lu]\n",
           frag_kb, frag_bytes, rounded_kb);
}


/* cleanup_and_return: closes and frees resources and returns the provided code */
static int cleanup_and_return(int code) {
    /* unmap pages */
    unmap_mapped_pages();

    /* close/free */
    close_elf_fd();
    free_phdrs();
    free_segments();
    free_mapped_pages();

    reset_state();

    return code;
}

static int cleanup_and_exit(void) {
    return cleanup_and_return(0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF-program>\n", argv[0]);
        return 1;
    }

    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    if (PAGE_SIZE == 0) PAGE_SIZE = 4096;

    const char *elf_path = argv[1];
    elf_fd = open(elf_path, O_RDONLY);
    if (elf_fd < 0) { fatal_perror("open"); }

    load_elf_headers(elf_path);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGSEGV, &sa, NULL) != 0) { fatal_perror("sigaction"); }

    uintptr_t entry = ehdr.e_entry;
    int (*entry_fn)(void) = (int (*)(void))entry;
    int ret = entry_fn();

    unsigned long frag_bytes = compute_internal_frag_bytes();
    double frag_kb = ((double)frag_bytes) / 1024.0;
    unsigned long rounded_kb = (frag_bytes + 1023) / 1024;

    printf("result: %d\n", ret);
    printf("Page faults: %lu\n", page_faults);
    printf("Page allocations: %lu\n", page_allocs);
    printf("Internal fragmentation: %.2fKB (%lu bytes) [rounded KB: %lu]\n",
           frag_kb, frag_bytes, rounded_kb);

    cleanup_and_exit();
    return 0;
}
