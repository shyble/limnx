/*
 * mm_test.c — Memory management tests
 * Tests: mmap, munmap, shm, mprotect, malloc/free
 * Portable — no arch-specific code.
 */
#include "../limntest.h"

static void test_mmap_munmap(void) {
    long addr = sys_mmap(1);  /* 1 page */
    lt_ok(addr > 0 && addr != -1, "mmap anonymous page");
    if (addr > 0 && addr != -1) {
        /* Write and read back */
        volatile char *p = (volatile char *)addr;
        p[0] = 'A';
        p[4095] = 'Z';
        lt_ok(p[0] == 'A' && p[4095] == 'Z', "mmap read/write works");
        sys_munmap(addr);
    } else {
        lt_ok(0, "mmap read/write works");
    }
}

static void test_shm(void) {
    long id = sys_shmget(42, 1);
    lt_ok(id >= 0, "shmget allocates region");
    if (id >= 0) {
        long addr = sys_shmat(id);
        lt_ok(addr > 0, "shmat maps region");
        if (addr > 0) {
            volatile int *p = (volatile int *)addr;
            *p = 12345;
            lt_ok(*p == 12345, "shm read/write");
            sys_shmdt(addr);
        } else {
            lt_ok(0, "shm read/write");
        }
    } else {
        lt_ok(0, "shmat maps region");
        lt_ok(0, "shm read/write");
    }
}

static void test_malloc_free(void) {
    void *p = malloc(256);
    lt_ok(p != (void *)0, "malloc returns non-NULL");
    if (p) {
        memset(p, 0xAB, 256);
        lt_ok(((unsigned char *)p)[0] == 0xAB, "malloc memory writable");
        free(p);
    } else {
        lt_ok(0, "malloc memory writable");
    }
}

static void test_cow_fork(void) {
    volatile int *shared = (volatile int *)malloc(sizeof(int));
    if (!shared) { lt_ok(0, "COW setup"); return; }
    *shared = 100;

    long child = sys_fork();
    if (child == 0) {
        /* Child: modify — should get COW copy */
        *shared = 200;
        sys_exit(*shared == 200 ? 0 : 1);
    }
    long st = sys_waitpid(child);
    lt_ok(st == 0, "child COW write succeeds");
    lt_ok(*shared == 100, "parent value unchanged after child COW");
    free((void *)shared);
}

static void test_large_mmap(void) {
    long addr = sys_mmap(16);  /* 16 pages = 64KB */
    lt_ok(addr > 0 && addr != -1, "mmap 16 pages");
    if (addr > 0 && addr != -1) {
        volatile char *p = (volatile char *)addr;
        p[0] = 'X';
        p[65535] = 'Y';
        lt_ok(p[0] == 'X' && p[65535] == 'Y', "large mmap read/write");
        sys_munmap(addr);
    } else {
        lt_ok(0, "large mmap read/write");
    }
}

static void test_malloc_stress(void) {
    int ok = 1;
    void *ptrs[32];
    for (int i = 0; i < 32; i++) {
        ptrs[i] = malloc(64 + i * 16);
        if (!ptrs[i]) { ok = 0; break; }
        memset(ptrs[i], (unsigned char)i, 64 + i * 16);
    }
    lt_ok(ok, "malloc 32 allocations");
    for (int i = 0; i < 32; i++)
        if (ptrs[i]) free(ptrs[i]);
}

static void test_mprotect_bounds(void) {
    long addr = sys_mmap(1);
    lt_ok(addr > 0, "mmap page for mprotect");
    if (addr <= 0) {
        lt_ok(0, "mprotect valid range succeeds");
        lt_ok(0, "page writable after mprotect(READ|WRITE)");
        lt_ok(0, "write to PROT_READ page faults");
        lt_ok(0, "mprotect rejects wrapping length");
        return;
    }
    volatile char *p = (volatile char *)addr;
    p[0] = 'M';

    long ret = sys_mprotect(addr, 4096, PROT_READ | PROT_WRITE);
    lt_ok(ret == 0 && p[0] == 'M', "mprotect valid range succeeds");
    p[1] = 'N';
    lt_ok(p[1] == 'N', "page writable after mprotect(READ|WRITE)");

    /* After PROT_READ a write must fault: the child is killed */
    long pid = sys_fork();
    if (pid == 0) {
        sys_mprotect(addr, 4096, PROT_READ);
        if (p[0] != 'M') sys_exit(97);
        p[0] = 'X';
        sys_exit(42);
    }
    long st = pid > 0 ? sys_waitpid(pid) : 42;
    lt_ok(st != 42 && st != 97, "write to PROT_READ page faults");

    /* addr + length wraps to 4096: used to pass the range check and walk
     * page tables far beyond user space. */
    long wrap_len = (long)(0UL - (unsigned long)addr + 4096UL);
    ret = sys_mprotect(addr, wrap_len, PROT_READ);
    lt_ok(ret == -22 /* EINVAL */, "mprotect rejects wrapping length");

    sys_munmap(addr);
}

int main(void) {
    lt_suite("mm");
    test_mmap_munmap();
    test_shm();
    test_malloc_free();
    test_cow_fork();
    test_large_mmap();
    test_malloc_stress();
    test_mprotect_bounds();
    return lt_done();
}
