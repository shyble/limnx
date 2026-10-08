#define pr_fmt(fmt) "[proc] " fmt
#include "klog.h"

#include "proc/process.h"
#include "proc/elf.h"
#include "kquiet.h"
#include "mm/vmm.h"
#include "mm/pmm.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "syscall/syscall.h"
#include "arch/serial.h"
#include "sync/spinlock.h"
#include "errno.h"
#include "kutil.h"
#include "arch/cpu.h"
#include "arch/paging.h"

static uint64_t next_pid = 1;
static process_t *proc_table[MAX_PROCS];
static spinlock_t proc_table_lock = SPINLOCK_INIT;

/* Copy the seccomp filter from parent to child. A sandboxed process must
 * never be able to produce an unsandboxed child, whatever path creates it
 * (fork, vfork, or spawn-from-path). */
void process_seccomp_inherit(process_t *child, const process_t *parent) {
    for (int i = 0; i < SECCOMP_WORDS; i++)
        child->seccomp_bits[i] = parent ? parent->seccomp_bits[i] : 0;
    if (!parent) {
        child->seccomp_strict = 0;
        child->seccomp_active = 0;
        return;
    }
    child->seccomp_strict = parent->seccomp_strict;
    child->seccomp_active = parent->seccomp_active;
}

uint64_t process_alloc_pid(void) {
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    uint64_t pid = next_pid++;
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return pid;
}

/* Forward-declare procfs hooks (defined in vfs.c, avoids circular include) */
extern void vfs_procfs_register_pid(uint64_t pid);
extern void vfs_procfs_unregister_pid(uint64_t pid);

int process_register(process_t *proc) {
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i] == NULL) {
            proc_table[i] = proc;
            spin_unlock_irqrestore(&proc_table_lock, flags);
            vfs_procfs_register_pid(proc->pid);
            return 0;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return -ENOMEM;
}

process_t *process_lookup(uint64_t pid) {
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i] && proc_table[i]->pid == pid) {
            process_t *p = proc_table[i];
            spin_unlock_irqrestore(&proc_table_lock, flags);
            return p;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return NULL;
}

/* Find a child process of the given parent. If exited_only=1, prefer exited children. */
process_t *process_find_child(uint64_t parent_pid, int exited_only) {
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    process_t *any_child = NULL;
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i] && proc_table[i]->parent_pid == parent_pid) {
            if (proc_table[i]->exited) {
                spin_unlock_irqrestore(&proc_table_lock, flags);
                return proc_table[i];
            }
            if (!any_child) any_child = proc_table[i];
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return exited_only ? NULL : any_child;
}

process_t *proc_table_get(int idx) {
    if (idx < 0 || idx >= MAX_PROCS) return NULL;
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    process_t *p = proc_table[idx];
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return p;
}

void process_unregister(uint64_t pid) {
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i] && proc_table[i]->pid == pid) {
            proc_table[i] = NULL;
            spin_unlock_irqrestore(&proc_table_lock, flags);
            return;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
}

/* Re-parent all children of dying_pid to new_parent (typically pid 1 / init) */
void process_reparent_children(uint64_t dying_pid, uint64_t new_parent) {
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i] && proc_table[i]->parent_pid == dying_pid)
            proc_table[i]->parent_pid = new_parent;
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
}

/*
 * Kernel-thread entry point for a user-space process.
 * Switches to the process's address space and jumps to ring 3 via SYSRETQ.
 */
static void process_enter_usermode(void) {
    thread_t *t = thread_get_current();
    process_t *proc = t->process;

    /* Set the kernel stack for SYSCALL re-entry */
    syscall_set_kernel_stack(t->stack_base + t->stack_size);

    /* Load the process's address space */
    arch_switch_address_space(proc->cr3);

    /* Set up Linux-standard initial stack layout.
     * musl/glibc _start reads: sp[0]=argc, sp[1..]=argv[], NULL, envp[], NULL, auxv[]
     * Our libc _start reads: rdi=argc, rsi=argv (both set for compatibility). */
    uint64_t sp = proc->user_stack_top;

    /* 1. Push argument strings */
    uint64_t str_addrs[PROC_MAX_ARGS];
    int nargs = 0;
    {
        int i = 0;
        while (i < proc->argv_buf_len && nargs < proc->argc) {
            int slen = 0;
            while (i + slen < proc->argv_buf_len && proc->argv_buf[i + slen] != '\0')
                slen++;
            slen++;
            sp -= (uint64_t)slen;
            char *dst = (char *)sp;
            for (int j = 0; j < slen; j++)
                dst[j] = proc->argv_buf[i + j];
            str_addrs[nargs] = sp;
            nargs++;
            i += slen;
        }
    }

    /* 2. Push environment strings */
    uint64_t env_addrs[64];
    int nenv = 0;

    /* Push process environment, then add defaults if missing */
    {
        int pos = 0;
        while (pos < proc->env_buf_len && nenv < 64) {
            int slen = 0;
            while (pos + slen < proc->env_buf_len && proc->env_buf[pos + slen] != '\0')
                slen++;
            if (slen == 0) { pos++; continue; }
            slen++;
            sp -= (uint64_t)slen;
            char *dst = (char *)sp;
            for (int j = 0; j < slen; j++)
                dst[j] = proc->env_buf[pos + j];
            env_addrs[nenv] = sp;
            nenv++;
            pos += slen;
        }
    }

    /* Add default environment entries if not already present */
    {
        const char *defaults[] = { "PATH=/bin", "HOME=/", "TERM=vt100", NULL };
        for (int d = 0; defaults[d] && nenv < 62; d++) {
            int klen = 0;
            while (defaults[d][klen] && defaults[d][klen] != '=') klen++;
            int found = 0;
            for (int e = 0; e < nenv; e++) {
                const char *existing = (const char *)env_addrs[e];
                int match = 1;
                for (int k = 0; k <= klen; k++) {
                    if (existing[k] != defaults[d][k]) { match = 0; break; }
                }
                if (match) { found = 1; break; }
            }
            if (!found) {
                int slen = 0;
                while (defaults[d][slen]) slen++;
                slen++;
                sp -= (uint64_t)slen;
                char *dst = (char *)sp;
                for (int j = 0; j < slen; j++) dst[j] = defaults[d][j];
                env_addrs[nenv] = sp;
                nenv++;
            }
        }
    }

    sp &= ~0xFULL;

    /* 3. Build Linux stack layout: auxv, envp, argv, argc
     * Calculate total size and align sp BEFORE writing,
     * so argc is exactly at sp[0] after alignment. */
    /* Auxiliary vector: AT_PAGESZ + AT_NULL (musl needs AT_PAGESZ at minimum) */
    #define AT_PAGESZ 6
    #define AT_PHDR   3
    #define AT_PHENT  4
    #define AT_PHNUM  5
    uint64_t total_slots = 1                   /* argc */
                         + (nargs + 1)         /* argv[] + NULL */
                         + (nenv + 1)          /* envp[] + NULL */
                         + 2                   /* AT_PAGESZ (key, value) */
                         + 2;                  /* AT_NULL (key, value) */
    uint64_t total_bytes = total_slots * 8;

    /* Align: sp must be 16-byte aligned at entry.
     * On x86_64, the ABI says sp % 16 == 0 at _start. */
    sp -= total_bytes;
    sp &= ~0xFULL;

    /* Now write from sp upward */
    uint64_t *slot = (uint64_t *)sp;
    int si = 0;

    /* argc */
    slot[si++] = (uint64_t)nargs;

    /* argv[] + NULL */
    uint64_t *argv_arr = &slot[si];
    for (int j = 0; j < nargs; j++)
        slot[si++] = str_addrs[j];
    slot[si++] = 0;  /* argv NULL terminator */

    /* envp[] + NULL */
    for (int j = 0; j < nenv; j++)
        slot[si++] = env_addrs[j];
    slot[si++] = 0;  /* envp NULL terminator */

    /* auxv: AT_PAGESZ then AT_NULL */
    slot[si++] = AT_PAGESZ;
    slot[si++] = PAGE_SIZE;
    slot[si++] = 0;  /* AT_NULL */
    slot[si++] = 0;

    uint64_t user_rsp = sp;
    uint64_t user_rdi = (uint64_t)nargs;
    uint64_t user_rsi = (uint64_t)argv_arr;

    /*
     * Fix GS state before entering user mode via SYSRETQ.
     *
     * In kernel mode, GS.base = percpu (set by syscall_init/smp_init).
     * For SYSRETQ, we need: GS.base = 0 (user), KERNEL_GS_BASE = percpu.
     * This ensures the next SWAPGS in syscall_entry correctly loads percpu.
     *
     * Read current GS.base; if non-zero (percpu), move it to KERNEL_GS_BASE
     * and clear GS.base.
     */
    arch_prepare_usermode_return();

    /* Jump to ring 3 via arch-specific mechanism (SYSRETQ / ERET) */
    arch_enter_usermode(proc->user_entry, user_rsp, user_rdi, user_rsi);
}

process_t *process_create(const uint8_t *code, uint64_t code_size) {
    process_t *proc = (process_t *)kmalloc(sizeof(process_t));
    if (!proc)
        return NULL;
    mem_zero(proc, sizeof(process_t));

    proc->pid = process_alloc_pid();
    proc->user_entry = USER_CODE_BASE;
    proc->user_stack_top = USER_STACK_TOP;

    /* Set parent PID from calling process (0 if kernel) */
    thread_t *caller = thread_get_current();
    proc->parent_pid = (caller && caller->process) ? caller->process->pid : 0;
    proc->exit_status = 0;
    proc->exited = 0;
    proc->wait_thread = NULL;

    /* Initialize process group — inherit parent's pgid */
    {
        process_t *parent = process_lookup(proc->parent_pid);
        proc->pgid = parent ? parent->pgid : proc->pid;
        proc->sid = parent ? parent->sid : proc->pid;
        /* Inherit uid/gid/euid/egid/caps from parent, or root defaults */
        if (parent) {
            proc->uid = parent->uid;
            proc->gid = parent->gid;
            proc->euid = parent->euid;
            proc->egid = parent->egid;
            proc->suid = parent->suid;
            proc->sgid = parent->sgid;
            proc->umask = parent->umask;
            proc->capabilities = parent->capabilities;
            proc->ngroups = parent->ngroups;
            for (int g = 0; g < parent->ngroups && g < MAX_SUPPL_GROUPS; g++)
                proc->groups[g] = parent->groups[g];
        } else {
            proc->uid = 0;
            proc->gid = 0;
            proc->euid = 0;
            proc->egid = 0;
            proc->suid = 0;
            proc->sgid = 0;
            proc->umask = 022;
            proc->capabilities = CAP_ALL;
            proc->ngroups = 0;
        }
    }

    /* Initialize security fields */
    proc->rlimit_mem_pages = 0;
    proc->rlimit_cpu_ticks = 0;
    proc->rlimit_nfds = 0;
    proc->used_mem_pages = 0;
    process_seccomp_inherit(proc, (caller && caller->process) ? caller->process : NULL);
    proc->audit_flags = 0;
    proc->daemon = 0;

    /* Initialize file descriptor table */
    for (int i = 0; i < MAX_FDS; i++) {
        proc->fd_table[i].node = NULL;
        proc->fd_table[i].offset = 0;
        proc->fd_table[i].pipe = NULL;
        proc->fd_table[i].pipe_write = 0;
        proc->fd_table[i].pty = NULL;
        proc->fd_table[i].pty_is_master = 0;
        proc->fd_table[i].unix_sock = NULL;
        proc->fd_table[i].eventfd = NULL;
        proc->fd_table[i].epoll = NULL;
        proc->fd_table[i].uring = NULL;
        proc->fd_table[i].tcp_conn_idx = -1;
        proc->fd_table[i].open_flags = 0;
        proc->fd_table[i].fd_flags = 0;
    }

    /* Initialize mmap table */
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        proc->mmap_table[i].used = 0;
        proc->mmap_table[i].shm_id = -1;
        proc->mmap_table[i].demand = 0;
    }
    proc->mmap_next_addr = MMAP_REGION_BASE;

    /* Initialize working directory */
    proc->cwd[0] = '/';
    proc->cwd[1] = '\0';

    /* Initialize signals */
    proc->pending_signals = 0;
    proc->signal_mask = 0;
    for (int i = 0; i < MAX_SIGNALS; i++) {
        proc->sig_handlers[i].sa_handler = SIG_DFL;
        proc->sig_handlers[i].sa_flags = 0;
    }
    proc->sig_queue.head = 0;
    proc->sig_queue.tail = 0;
    proc->sig_queue.count = 0;
    proc->signal_depth = 0;
    proc->restart_pending = 0;

    /* Initialize argv */
    proc->argc = 0;
    proc->argv_buf_len = 0;

    /* Initialize env */
    proc->env_count = 0;
    proc->env_buf_len = 0;

    /* Initialize TCP connection tracking */
    for (int i = 0; i < 8; i++)
        proc->tcp_conns[i] = 0;

    /* Create a new address space (PML4 with kernel upper-half cloned) */
    proc->cr3 = vmm_create_address_space();
    if (proc->cr3 == 0) {
        pr_err("failed to create address space\n");
        kfree(proc);
        return NULL;
    }

    /* Map user code pages */
    uint64_t code_pages = (code_size + PAGE_SIZE - 1) / PAGE_SIZE;
    for (uint64_t i = 0; i < code_pages; i++) {
        uint64_t phys = pmm_alloc_page();
        if (phys == 0) {
            pr_err("out of memory for code\n");
            kfree(proc);
            return NULL;
        }

        /* Copy code bytes into the physical page via HHDM */
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(phys);
        uint64_t offset = i * PAGE_SIZE;
        uint64_t chunk = code_size - offset;
        if (chunk > PAGE_SIZE) chunk = PAGE_SIZE;

        for (uint64_t j = 0; j < chunk; j++)
            dst[j] = code[offset + j];
        /* Zero remaining bytes in the page */
        for (uint64_t j = chunk; j < PAGE_SIZE; j++)
            dst[j] = 0;

        /* Map into user address space: readable + writable + executable + user */
        uint64_t virt = USER_CODE_BASE + offset;
        if (vmm_map_page_in(proc->cr3, virt, phys, PTE_USER | PTE_WRITABLE) != 0) {
            pr_err("failed to map code page\n");
            kfree(proc);
            return NULL;
        }
    }

    /* Map user stack pages (grows down from USER_STACK_TOP) */
    uint64_t stack_pages = USER_STACK_SIZE / PAGE_SIZE;
    uint64_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    for (uint64_t i = 0; i < stack_pages; i++) {
        uint64_t phys = pmm_alloc_page();
        if (phys == 0) {
            pr_err("out of memory for stack\n");
            kfree(proc);
            return NULL;
        }

        /* Zero the stack page */
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(phys);
        for (uint64_t j = 0; j < PAGE_SIZE; j++)
            dst[j] = 0;

        uint64_t virt = stack_bottom + i * PAGE_SIZE;
        if (vmm_map_page_in(proc->cr3, virt, phys,
                            PTE_USER | PTE_WRITABLE | PTE_NX) != 0) {
            pr_err("failed to map stack page\n");
            kfree(proc);
            return NULL;
        }
    }

    /* Create a kernel thread that will transition to user mode */
    thread_t *t = thread_create(process_enter_usermode, 0);
    if (!t) {
        pr_err("failed to create thread\n");
        kfree(proc);
        return NULL;
    }

    t->process = proc;
    proc->main_thread = t;
    if (process_register(proc) < 0) {
        pr_err("process table full\n");
        kfree(proc);
        return NULL;
    }
    /* NOTE: caller must call sched_add(proc->main_thread) after setup */

    if (!kernel_quiet) pr_info("Created process %lu (cr3=%lx, entry=%lx)\n",
        proc->pid, proc->cr3, proc->user_entry);

    return proc;
}

process_t *process_create_from_elf(const uint8_t *elf, uint64_t size) {
    elf_load_result_t result;
    if (elf_load(elf, size, &result) != 0)
        return NULL;

    process_t *proc = (process_t *)kmalloc(sizeof(process_t));
    if (proc) mem_zero(proc, sizeof(process_t));
    if (!proc)
        return NULL;

    proc->pid = process_alloc_pid();
    proc->user_entry = result.entry;
    proc->user_stack_top = USER_STACK_TOP;
    proc->cr3 = result.cr3;
    proc->brk_base = result.brk_base;
    proc->brk_current = result.brk_base;

    /* Set parent PID from calling process (0 if kernel) */
    thread_t *caller = thread_get_current();
    proc->parent_pid = (caller && caller->process) ? caller->process->pid : 0;
    proc->exit_status = 0;
    proc->exited = 0;
    proc->wait_thread = NULL;

    /* Initialize process group — inherit parent's pgid */
    {
        process_t *parent = process_lookup(proc->parent_pid);
        proc->pgid = parent ? parent->pgid : proc->pid;
        proc->sid = parent ? parent->sid : proc->pid;
        /* Inherit uid/gid/euid/egid/caps from parent, or root defaults */
        if (parent) {
            proc->uid = parent->uid;
            proc->gid = parent->gid;
            proc->euid = parent->euid;
            proc->egid = parent->egid;
            proc->suid = parent->suid;
            proc->sgid = parent->sgid;
            proc->umask = parent->umask;
            proc->capabilities = parent->capabilities;
            proc->ngroups = parent->ngroups;
            for (int g = 0; g < parent->ngroups && g < MAX_SUPPL_GROUPS; g++)
                proc->groups[g] = parent->groups[g];
        } else {
            proc->uid = 0;
            proc->gid = 0;
            proc->euid = 0;
            proc->egid = 0;
            proc->suid = 0;
            proc->sgid = 0;
            proc->umask = 022;
            proc->capabilities = CAP_ALL;
            proc->ngroups = 0;
        }
    }

    /* Initialize security fields */
    proc->rlimit_mem_pages = 0;
    proc->rlimit_cpu_ticks = 0;
    proc->rlimit_nfds = 0;
    proc->used_mem_pages = 0;
    process_seccomp_inherit(proc, (caller && caller->process) ? caller->process : NULL);
    proc->audit_flags = 0;
    proc->daemon = 0;

    /* Initialize file descriptor table */
    for (int i = 0; i < MAX_FDS; i++) {
        proc->fd_table[i].node = NULL;
        proc->fd_table[i].offset = 0;
        proc->fd_table[i].pipe = NULL;
        proc->fd_table[i].pipe_write = 0;
        proc->fd_table[i].pty = NULL;
        proc->fd_table[i].pty_is_master = 0;
        proc->fd_table[i].unix_sock = NULL;
        proc->fd_table[i].eventfd = NULL;
        proc->fd_table[i].epoll = NULL;
        proc->fd_table[i].uring = NULL;
        proc->fd_table[i].tcp_conn_idx = -1;
        proc->fd_table[i].open_flags = 0;
        proc->fd_table[i].fd_flags = 0;
    }

    /* Initialize mmap table */
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        proc->mmap_table[i].used = 0;
        proc->mmap_table[i].shm_id = -1;
        proc->mmap_table[i].demand = 0;
    }
    proc->mmap_next_addr = MMAP_REGION_BASE;

    /* Initialize working directory */
    proc->cwd[0] = '/';
    proc->cwd[1] = '\0';

    /* Initialize signals */
    proc->pending_signals = 0;
    proc->signal_mask = 0;
    for (int i = 0; i < MAX_SIGNALS; i++) {
        proc->sig_handlers[i].sa_handler = SIG_DFL;
        proc->sig_handlers[i].sa_flags = 0;
    }
    proc->sig_queue.head = 0;
    proc->sig_queue.tail = 0;
    proc->sig_queue.count = 0;
    proc->signal_depth = 0;
    proc->restart_pending = 0;

    /* Initialize argv */
    proc->argc = 0;
    proc->argv_buf_len = 0;

    /* Initialize env */
    proc->env_count = 0;
    proc->env_buf_len = 0;

    /* Initialize TCP connection tracking */
    for (int i = 0; i < 8; i++)
        proc->tcp_conns[i] = 0;

    /* Map user stack pages (grows down from USER_STACK_TOP) */
    uint64_t stack_pages = USER_STACK_SIZE / PAGE_SIZE;
    uint64_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    for (uint64_t i = 0; i < stack_pages; i++) {
        uint64_t phys = pmm_alloc_page();
        if (phys == 0) {
            pr_err("out of memory for stack\n");
            kfree(proc);
            return NULL;
        }

        /* Zero the stack page */
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(phys);
        for (uint64_t j = 0; j < PAGE_SIZE; j++)
            dst[j] = 0;

        uint64_t virt = stack_bottom + i * PAGE_SIZE;
        if (vmm_map_page_in(proc->cr3, virt, phys,
                            PTE_USER | PTE_WRITABLE | PTE_NX) != 0) {
            pr_err("failed to map stack page\n");
            kfree(proc);
            return NULL;
        }
    }

    /* Create a kernel thread that will transition to user mode */
    thread_t *t = thread_create(process_enter_usermode, 0);
    if (!t) {
        pr_err("failed to create thread\n");
        kfree(proc);
        return NULL;
    }

    t->process = proc;
    proc->main_thread = t;
    if (process_register(proc) < 0) {
        pr_err("process table full\n");
        kfree(proc);
        return NULL;
    }
    /* NOTE: caller must call sched_add(proc->main_thread) after setup */

    if (!kernel_quiet) pr_info("Created process %lu (cr3=%lx, entry=%lx)\n",
        proc->pid, proc->cr3, proc->user_entry);

    return proc;
}

void process_reap(process_t *proc) {
    if (!proc) return;
    thread_t *me = thread_get_current();
    while (!proc->exited) {
        proc->wait_thread = me;
        arch_memory_barrier();
        if (proc->exited) {
            proc->wait_thread = NULL;
            break;
        }
        sched_block(me);
        proc->wait_thread = NULL;
    }
    process_unregister(proc->pid);
    kfree(proc);
}

/* --- fork --- */

static void fork_child_entry(void) {
    thread_t *t = thread_get_current();
    process_t *proc = t->process;

    syscall_set_kernel_stack(t->stack_base + t->stack_size);
    arch_switch_address_space(proc->cr3);
    arch_prepare_usermode_return();
    arch_set_tls_base(t->fs_base);
#if defined(__aarch64__)
#endif
    arch_enter_forked_child(&proc->fork_ctx);
}

process_t *process_fork(process_t *parent, const fork_context_t *ctx) {
    process_t *child = (process_t *)kmalloc(sizeof(process_t));
    if (!child) return NULL;
    mem_zero(child, sizeof(process_t));

    child->pid = process_alloc_pid();
    child->parent_pid = parent->pid;
    child->pgid = parent->pgid;
    child->sid = parent->sid;
    child->uid = parent->uid;
    child->gid = parent->gid;
    child->euid = parent->euid;
    child->egid = parent->egid;
    child->suid = parent->suid;
    child->sgid = parent->sgid;
    child->umask = parent->umask;
    child->ngroups = parent->ngroups;
    for (int g = 0; g < parent->ngroups && g < MAX_SUPPL_GROUPS; g++)
        child->groups[g] = parent->groups[g];
    child->capabilities = parent->capabilities;
    child->rlimit_mem_pages = parent->rlimit_mem_pages;
    child->rlimit_cpu_ticks = parent->rlimit_cpu_ticks;
    child->rlimit_nfds = parent->rlimit_nfds;
    child->used_mem_pages = parent->used_mem_pages;
    process_seccomp_inherit(child, parent);
    child->audit_flags = parent->audit_flags;
    child->daemon = 0;  /* forked children are never daemons */
    child->exit_status = 0;
    child->exited = 0;
    child->wait_thread = NULL;
    child->ns_id = parent->ns_id;
    child->user_entry = parent->user_entry;
    child->user_stack_top = parent->user_stack_top;
    child->pending_signals = 0;
    child->signal_mask = parent->signal_mask;  /* inherit signal mask */
    child->sig_queue.head = 0;
    child->sig_queue.tail = 0;
    child->sig_queue.count = 0;
    child->signal_depth = 0;
    { /* Copy fork context (avoid memcpy on ARM64) */
        const uint8_t *s = (const uint8_t *)ctx;
        uint8_t *d = (uint8_t *)&child->fork_ctx;
        for (unsigned i = 0; i < sizeof(fork_context_t); i++) d[i] = s[i];
    }
    for (int i = 0; i < 32; i++) child->name[i] = parent->name[i];

    /* Clone address space with COW */
    child->cr3 = vmm_clone_cow(parent->cr3,
                               parent->mmap_table, MMAP_MAX_ENTRIES);
    if (child->cr3 == 0) { kfree(child); return NULL; }

    /* Copy fd_table (pipe ref increments done by caller in syscall.c) */
    for (int i = 0; i < MAX_FDS; i++)
        child->fd_table[i] = parent->fd_table[i];

    /* Copy mmap_table (shm ref increments done by caller in syscall.c) */
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++)
        child->mmap_table[i] = parent->mmap_table[i];
    child->mmap_next_addr = parent->mmap_next_addr;

    /* Copy cwd */
    for (int i = 0; i < MAX_PATH; i++)
        child->cwd[i] = parent->cwd[i];

    /* Copy argv */
    child->argc = parent->argc;
    child->argv_buf_len = parent->argv_buf_len;
    for (int i = 0; i < parent->argv_buf_len; i++)
        child->argv_buf[i] = parent->argv_buf[i];

    /* Copy env */
    child->env_count = parent->env_count;
    child->env_buf_len = parent->env_buf_len;
    for (int i = 0; i < parent->env_buf_len; i++)
        child->env_buf[i] = parent->env_buf[i];

    /* Copy signal handlers */
    for (int i = 0; i < MAX_SIGNALS; i++)
        child->sig_handlers[i] = parent->sig_handlers[i];

    /* TCP connections are NOT inherited by forked children.
     * They are per-process kernel resources (like Linux). If inherited,
     * the child's sys_exit would close the parent's connections. */
    for (int i = 0; i < 8; i++)
        child->tcp_conns[i] = 0;

    /* fork_saved was filled by process_fork_set_context() before this call */

    /* Create kernel thread for child */
    thread_t *ct = thread_create(fork_child_entry, 0);
    if (!ct) { kfree(child); return NULL; }
    ct->process = child;
    ct->fs_base = parent->main_thread->fs_base;  /* inherit TLS */
    child->main_thread = ct;

    if (process_register(child) < 0) { kfree(child); return NULL; }
    /* NOTE: caller must call sched_add(child->main_thread) after
     * incrementing pipe/pty/unix_sock ref counts. */
    return child;
}

/*
 * process_fork_vfork — vfork variant: child shares parent's address space.
 * Used for clone(CLONE_VM|CLONE_VFORK). Parent blocks until child execs/exits.
 */
process_t *process_fork_vfork(process_t *parent, const fork_context_t *ctx) {
    process_t *child = (process_t *)kmalloc(sizeof(process_t));
    if (!child) return NULL;
    mem_zero(child, sizeof(process_t));

    child->pid = process_alloc_pid();
    child->parent_pid = parent->pid;
    child->pgid = parent->pgid;
    child->sid = parent->sid;
    child->uid = parent->uid;
    child->gid = parent->gid;
    child->euid = parent->euid;
    child->egid = parent->egid;
    child->suid = parent->suid;
    child->sgid = parent->sgid;
    child->umask = parent->umask;
    child->capabilities = parent->capabilities;
    child->ngroups = parent->ngroups;
    for (int g = 0; g < parent->ngroups && g < MAX_SUPPL_GROUPS; g++)
        child->groups[g] = parent->groups[g];
    child->rlimit_mem_pages = parent->rlimit_mem_pages;
    child->rlimit_cpu_ticks = parent->rlimit_cpu_ticks;
    child->rlimit_nfds = parent->rlimit_nfds;
    process_seccomp_inherit(child, parent);
    child->audit_flags = parent->audit_flags;
    child->daemon = 0;
    child->exit_status = 0;
    child->exited = 0;
    child->ns_id = parent->ns_id;
    child->user_entry = parent->user_entry;
    child->user_stack_top = parent->user_stack_top;
    child->signal_mask = parent->signal_mask;
    { const uint8_t *s = (const uint8_t *)ctx;
      uint8_t *d = (uint8_t *)&child->fork_ctx;
      for (unsigned i = 0; i < sizeof(fork_context_t); i++) d[i] = s[i]; }
    for (int i = 0; i < 32; i++) child->name[i] = parent->name[i];

    /* VFORK: share parent's address space (no COW clone) */
    child->cr3 = parent->cr3;
    child->vfork_parent = parent;

    /* Copy fd_table */
    for (int i = 0; i < MAX_FDS; i++)
        child->fd_table[i] = parent->fd_table[i];

    /* Do NOT copy mmap_table — vfork child doesn't own any mappings */
    child->mmap_next_addr = parent->mmap_next_addr;

    /* Copy cwd, argv, env, signal handlers */
    for (int i = 0; i < MAX_PATH; i++) child->cwd[i] = parent->cwd[i];
    child->argc = parent->argc;
    child->argv_buf_len = parent->argv_buf_len;
    for (int i = 0; i < parent->argv_buf_len; i++)
        child->argv_buf[i] = parent->argv_buf[i];
    child->env_count = parent->env_count;
    child->env_buf_len = parent->env_buf_len;
    for (int i = 0; i < parent->env_buf_len; i++)
        child->env_buf[i] = parent->env_buf[i];
    for (int i = 0; i < MAX_SIGNALS; i++)
        child->sig_handlers[i] = parent->sig_handlers[i];

    /* brk: inherit parent's */
    child->brk_base = parent->brk_base;
    child->brk_current = parent->brk_current;

    /* No TCP connections */
    for (int i = 0; i < 8; i++) child->tcp_conns[i] = 0;

    thread_t *ct = thread_create(fork_child_entry, 0);
    if (!ct) { kfree(child); return NULL; }
    ct->process = child;
    ct->fs_base = parent->main_thread->fs_base;
    child->main_thread = ct;

    if (process_register(child) < 0) { kfree(child); return NULL; }
    return child;
}

/* --- Signal delivery --- */

int process_deliver_signal(process_t *proc, int signum) {
    if (!proc || !proc->main_thread)
        return -1;
    if (signum < 1 || signum >= MAX_SIGNALS)
        return -1;

    /* SIGKILL and SIGSTOP cannot be blocked or caught */
    if (signum == SIGKILL) {
        proc->exit_status = -(int64_t)signum;
        if (proc->main_thread->state == THREAD_READY) {
            if (sched_remove(proc->main_thread))
                proc->exited = 1;
        }
        proc->main_thread->state = THREAD_DEAD;
        /* Wake any thread blocked in waitpid for this process */
        if (proc->exited && proc->wait_thread) {
            thread_t *waiter = proc->wait_thread;
            proc->wait_thread = NULL;
            sched_wake(waiter);
        }
        pr_info("Process %lu killed (SIGKILL)\n", proc->pid);
        return 0;
    }
    if (signum == SIGSTOP) {
        if (proc->main_thread->state == THREAD_READY) {
            sched_remove(proc->main_thread);
        }
        proc->main_thread->state = THREAD_STOPPED;
        pr_info("Process %lu stopped (SIGSTOP)\n", proc->pid);
        return 0;
    }
    if (signum == SIGCONT) {
        if (proc->main_thread->state == THREAD_STOPPED) {
            proc->main_thread->state = THREAD_READY;
            sched_add(proc->main_thread);
            pr_info("Process %lu continued (SIGCONT)\n", proc->pid);
        }
        return 0;
    }

    /* If signal is already pending and queue has space, enqueue duplicate */
    uint32_t bit = 1U << (uint32_t)signum;
    if (proc->pending_signals & bit) {
        signal_queue_t *q = &proc->sig_queue;
        if (q->count < SIG_QUEUE_SIZE) {
            q->signum[q->tail] = signum;
            q->tail = (q->tail + 1) % SIG_QUEUE_SIZE;
            q->count++;
        }
        /* else: queue full, signal lost (best effort) */
    } else {
        proc->pending_signals |= bit;
    }
    return 0;
}

/* May sender signal target? Root or CAP_KILL may signal anyone; otherwise
 * the sender's real or effective uid must match the target's real or saved
 * uid. A NULL sender is the kernel itself. */
int process_may_signal(const process_t *sender, const process_t *target) {
    if (!sender || sender->euid == 0 || (sender->capabilities & CAP_KILL))
        return 1;
    return sender->uid == target->uid || sender->uid == target->suid ||
           sender->euid == target->uid || sender->euid == target->suid;
}

/* Signal every process in a group that sender may signal. Returns 0 if at
 * least one was signalled, -EPERM if the group exists but none could be,
 * -ESRCH otherwise. */
int process_kill_group_from(const process_t *sender, uint64_t pgid, int signum) {
    uint64_t flags;
    process_t *targets[MAX_PROCS];
    int n = 0, denied = 0;

    /* Collect targets under lock, deliver signals after releasing */
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i] && proc_table[i]->pgid == pgid) {
            if (process_may_signal(sender, proc_table[i]))
                targets[n++] = proc_table[i];
            else
                denied++;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);

    int count = 0;
    for (int i = 0; i < n; i++) {
        if (process_deliver_signal(targets[i], signum) == 0)
            count++;
    }
    if (count > 0) return 0;
    return denied > 0 ? -EPERM : -ESRCH;
}

int process_kill_group(uint64_t pgid, int signum) {
    return process_kill_group_from(NULL, pgid, signum);
}

/* --- Procfs accessor helpers (avoids circular include with vfs.h) --- */

uint64_t procfs_get_pid(process_t *p) { return p->pid; }
uint64_t procfs_get_ppid(process_t *p) { return p->parent_pid; }
const char *procfs_get_name(process_t *p) { return p->name; }
const char *procfs_get_cwd(process_t *p) { return p->cwd; }
uint16_t procfs_get_uid(process_t *p) { return p->uid; }
uint16_t procfs_get_gid(process_t *p) { return p->gid; }
uint32_t procfs_get_caps(process_t *p) { return p->capabilities; }
uint64_t procfs_get_mem_pages(process_t *p) { return p->used_mem_pages; }
uint32_t procfs_get_pending_signals(process_t *p) { return p->pending_signals; }
uint32_t procfs_get_signal_mask(process_t *p) { return p->signal_mask; }
uint32_t procfs_get_ns_id(process_t *p) { return p->ns_id; }
uint64_t procfs_get_sid(process_t *p) { return p->sid; }
int procfs_get_argc(process_t *p) { return p->argc; }
const char *procfs_get_argv_buf(process_t *p) { return p->argv_buf; }
int procfs_get_argv_buf_len(process_t *p) { return p->argv_buf_len; }
uint8_t procfs_get_thread_state(process_t *p) {
    if (!p->main_thread) return 2; /* DEAD */
    return (uint8_t)p->main_thread->state;
}
