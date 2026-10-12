# SmartLoader: a demand-paging ELF loader in C

A loader for 32-bit ELF executables that maps **nothing** up front. Every page is brought in the first time the program touches it, the same way Linux demand paging works. There is no `execve`: the loader parses the ELF file itself and jumps straight to its entry point.

Built for the Operating Systems course (CSE231) at IIIT-Delhi.

## How it works

1. **Parse.** Read the ELF header and program headers, and record every `PT_LOAD` segment: virtual address, file offset, file size, memory size and R/W/X flags.
2. **Jump.** Install a `SIGSEGV` handler with `sigaction`, then call the entry point with no segment mapped.
3. **Fault.** The first instruction faults. The handler:
   - finds which `PT_LOAD` segment owns the faulting address (a fault outside every segment is a real crash, and exits)
   - `mmap`s exactly one 4 KB page at that address
   - copies in only the file bytes that overlap the page, and leaves the rest zero. That handles the boundary where a segment's file-backed part ends and its `.bss` begins.
   - `mprotect`s the page to the segment's real permissions
4. **Repeat** until the program returns, then report page faults, page allocations and internal fragmentation (bytes allocated but never backed by the segment).

## Run it

Needs a 32-bit toolchain (`sudo apt install gcc-multilib`).

```bash
make
./loader_1 ./fib     # fib(40), recursive
./loader_1 ./sum     # sums a 4 KB-aligned 1024-int array
```

```
result: 102334155
Page faults: 1
Page allocations: 1
Internal fragmentation: 3.89KB (3982 bytes)

result: 2048
Page faults: 3
Page allocations: 3
Internal fragmentation: 7.88KB (8066 bytes)
```

The test programs are freestanding (`-nostdlib -no-pie`, their own `_start`, no libc), because the loader sets up no dynamic linker.

## Files

| File | |
|---|---|
| `loader_1.c` | the loader |
| `fib.c`, `sum.c` | freestanding test programs |
| `design.pdf` | design notes |

Concepts: ELF format, demand paging, page faults, `SIGSEGV` with `SA_SIGINFO`, `mmap` / `mprotect`, page alignment and internal fragmentation.
