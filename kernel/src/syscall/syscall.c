#define pr_fmt(fmt) "[syscall] " fmt
#include "klog.h"

#include "syscall/syscall.h"
#include "syscall/syscall_internal.h"
#include "sched/sched.h"
#include "sched/thread.h"
#include "proc/process.h"
#include "proc/elf.h"
#include "fs/vfs.h"
#include "mm/pmm.h"
#include "mm/vmm.h"
#include "mm/kheap.h"
#include "net/net.h"
#include "net/tcp.h"
#include "pty/pty.h"
#include "ipc/unix_sock.h"
#include "ipc/eventfd.h"
#include "ipc/agent_reg.h"
#include "ipc/epoll.h"
#include "ipc/infer_svc.h"
#include "ipc/uring.h"
#include "ipc/cap_token.h"
#include "ipc/agent_ns.h"
#include "sync/futex.h"
#include "ipc/taskgraph.h"
#include "ipc/supervisor.h"
#include "mm/swap.h"
#include "blk/limnfs.h"
#include "arch/percpu.h"
#include "arch/serial.h"
#include "arch/cpu.h"
#include "arch/paging.h"
#include "arch/syscall_arch.h"

/* --- Shared helpers (non-static, declared in syscall_internal.h) --- */

int validate_user_ptr(uint64_t ptr, uint64_t len) {
    if (ptr == 0 || ptr >= USER_ADDR_MAX)
        return -1;
    if (len > 0 && len > USER_ADDR_MAX - ptr)
        return -1;
    return 0;
}

int copy_string_from_user(const char *user_src, char *kern_dst,
                                  uint64_t max_len) {
    if (!user_src || (uint64_t)user_src >= USER_ADDR_MAX)
        return -1;

    for (uint64_t i = 0; i < max_len - 1; i++) {
        if ((uint64_t)(user_src + i) >= USER_ADDR_MAX)
            return -1;
        kern_dst[i] = user_src[i];
        if (user_src[i] == '\0')
            return 0;
    }
    kern_dst[max_len - 1] = '\0';
    return 0;
}

/* Resolve user path (prepend cwd if relative) */
void resolve_user_path(process_t *proc, const char *path, char *out) {
    if (path[0] == '/') {
        /* Absolute path — copy as-is */
        int i = 0;
        while (path[i] && i < MAX_PATH - 1) {
            out[i] = path[i];
            i++;
        }
        out[i] = '\0';
        return;
    }

    /* Relative path — prepend cwd */
    int pos = 0;
    const char *cwd = proc->cwd;
    while (cwd[pos] && pos < MAX_PATH - 1) {
        out[pos] = cwd[pos];
        pos++;
    }

    /* Add separator if cwd doesn't end with '/' */
    if (pos > 0 && out[pos - 1] != '/' && pos < MAX_PATH - 1)
        out[pos++] = '/';

    /* Append relative path */
    int j = 0;
    while (path[j] && pos < MAX_PATH - 1)
        out[pos++] = path[j++];
    out[pos] = '\0';
}

/* Check if fd slot is free (no node, no pipe, no pty) */
int fd_is_free(const fd_entry_t *e) {
    return e->node == NULL && e->pipe == NULL && e->pty == NULL
        && e->unix_sock == NULL && e->eventfd == NULL
        && e->epoll == NULL && e->uring == NULL
        && e->tcp_conn_idx < 0;
}

/* --- Permission helper --- */

/* Check if process belongs to a group (primary or supplementary) */
static int process_in_group(const process_t *proc, uint16_t primary_gid,
                            uint16_t gid) {
    if (primary_gid == gid) return 1;
    for (int i = 0; i < proc->ngroups && i < MAX_SUPPL_GROUPS; i++) {
        if (proc->groups[i] == gid) return 1;
    }
    return 0;
}

/* Check rwx access to a node. mask is a combination of VFS_PERM_READ,
 * VFS_PERM_WRITE and VFS_PERM_EXEC. Root bypasses read/write checks but,
 * as on Unix, may only execute a file that has at least one x bit set. */
static int node_access_for(const process_t *proc, uint16_t uid, uint16_t gid,
                           const vfs_node_t *node, int mask) {
    if (uid == 0) {
        if ((mask & VFS_PERM_EXEC) && node->type != VFS_DIRECTORY &&
            !(node->mode & 0111))
            return -EACCES;
        return 0;
    }
    uint16_t perm_bits;
    if (uid == node->uid)
        perm_bits = (node->mode >> 6) & 7;
    else if (process_in_group(proc, gid, node->gid))
        perm_bits = (node->mode >> 3) & 7;
    else
        perm_bits = node->mode & 7;
    if ((perm_bits & mask) != mask)
        return -EACCES;
    return 0;
}

int check_node_access(const process_t *proc, const vfs_node_t *node, int mask) {
    return node_access_for(proc, proc->euid, proc->egid, node, mask);
}

/* Same check using the real ids, as access(2) requires. */
int check_node_access_real(const process_t *proc, const vfs_node_t *node, int mask) {
    return node_access_for(proc, proc->uid, proc->gid, node, mask);
}

int check_file_perm(const process_t *proc, const vfs_node_t *node, uint8_t access) {
    int mask = 0;
    if (access == O_RDONLY || access == O_RDWR)
        mask |= VFS_PERM_READ;
    if (access == O_WRONLY || access == O_RDWR)
        mask |= VFS_PERM_WRITE;
    return check_node_access(proc, node, mask);
}

/* Check write permission on the directory that contains path. */
int check_parent_write(const process_t *proc, const char *path) {
    char parent_path[MAX_PATH], base_name[MAX_PATH];
    vfs_path_split(path, parent_path, base_name);
    int parent_idx = vfs_resolve_path(parent_path);
    if (parent_idx < 0)
        return -ENOENT;
    vfs_node_t *parent_node = vfs_get_node(parent_idx);
    if (!parent_node)
        return -ENOENT;
    return check_node_access(proc, parent_node, VFS_PERM_WRITE);
}

/* Count open fds for a process */
int count_open_fds(process_t *proc) {
    int count = 0;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!fd_is_free(&proc->fd_table[i]))
            count++;
    }
    return count;
}

/* --- Dispatch table --- */

static syscall_fn_t syscall_table[SYS_NR] __attribute__((section(".data"))) = {

    /* ---- Both architectures ---- */
    [SYS_READ]             = sys_read,
    [SYS_WRITE]            = sys_fwrite,
    [SYS_CLOSE]            = sys_close,
    [SYS_FSTAT]            = sys_fstat,
    [SYS_LSEEK]            = sys_seek,
    [SYS_POLL]             = sys_poll,
    [SYS_PPOLL]            = sys_ppoll,
    [SYS_MMAP]             = sys_mmap,
    [SYS_MPROTECT]         = sys_mprotect,
    [SYS_MUNMAP]           = sys_munmap,
    [SYS_RT_SIGACTION]     = sys_sigaction,
    [SYS_RT_SIGPROCMASK]   = sys_sigprocmask,
    [SYS_RT_SIGRETURN]     = sys_sigreturn,
    [SYS_IOCTL]            = sys_ioctl,
    [SYS_PIPE2]            = sys_pipe2,
    [SYS_SCHED_YIELD]      = sys_yield,
    [SYS_NANOSLEEP]        = sys_nanosleep,
    [SYS_GETPID]           = sys_getpid,
    [SYS_SOCKET]           = sys_socket,
    [SYS_CONNECT]          = sys_tcp_connect,
    [SYS_ACCEPT]           = sys_tcp_accept,
    [SYS_SENDTO]           = sys_sendto,
    [SYS_RECVFROM]         = sys_recvfrom,
    [SYS_BIND]             = sys_bind,
    [SYS_LISTEN]           = sys_tcp_listen,
    [SYS_EXECVE]           = sys_execve,
    [SYS_EXIT]             = sys_exit,
    [SYS_WAIT4]            = sys_waitpid,
    [SYS_KILL]             = sys_kill,
    [SYS_FCNTL]            = sys_fcntl,
    [SYS_TRUNCATE]         = sys_truncate,
    [SYS_GETCWD]           = sys_getcwd,
    [SYS_CHDIR]            = sys_chdir,
    [SYS_FCHOWN]           = sys_fchown,
    [SYS_UMASK]            = sys_umask,
    [SYS_GETRLIMIT]        = sys_getrlimit,
    [SYS_SETRLIMIT]        = sys_setrlimit,
    [SYS_GETUID]           = sys_getuid,
    [SYS_GETGID]           = sys_getgid,
    [SYS_SETUID]           = sys_setuid,
    [SYS_SETGID]           = sys_setgid,
    [SYS_GETEUID]          = sys_geteuid,
    [SYS_GETEGID]          = sys_getegid,
    [SYS_SETPGID]          = sys_setpgid,
    [SYS_SETSID]           = sys_setsid,
    [SYS_GETSID]           = sys_getsid,
    [SYS_GETGROUPS]        = sys_getgroups,
    [SYS_SETGROUPS]        = sys_setgroups,
    [SYS_MOUNT]            = sys_mount,
    [SYS_UMOUNT2]          = sys_umount,
    [SYS_FUTEX]            = sys_futex_wait,
    [SYS_CLOCK_GETTIME]    = sys_clock_gettime,
    [SYS_EPOLL_CTL]        = sys_epoll_ctl,
    [SYS_EPOLL_CREATE1]    = sys_epoll_create,
    [SYS_EVENTFD2]         = sys_eventfd,
    [SYS_BRK]              = sys_brk,
    [SYS_WRITEV]           = sys_writev,
    [SYS_GETPPID]          = sys_getppid,
    [SYS_SET_TID_ADDRESS]  = sys_set_tid_address,
    [SYS_EXIT_GROUP]       = sys_exit_group,
    [SYS_UNAME]            = sys_uname,
    [SYS_FTRUNCATE]        = sys_ftruncate,
    [SYS_GETDENTS64]       = sys_getdents64,
    [SYS_GETTID]           = sys_gettid,
    [SYS_TGKILL]           = sys_tgkill,
    [SYS_CLOCK_GETRES]     = sys_clock_getres,
    [SYS_DUP3]             = sys_dup3,
    [SYS_READV]            = sys_readv,
    [SYS_SECCOMP]          = sys_seccomp,
    [SYS_GETRANDOM]        = sys_getrandom,
    [SYS_SET_ROBUST_LIST]  = sys_set_robust_list,
    [SYS_RSEQ]             = sys_rseq,
    [SYS_IO_URING_SETUP]   = sys_uring_setup,
    [SYS_IO_URING_ENTER]   = sys_uring_enter,
    /* *at() variants — wrappers that skip dirfd arg, both archs */
    [SYS_OPENAT]           = sys_openat,
    [SYS_MKDIRAT]          = sys_mkdirat,
    [SYS_FSTATAT]          = sys_fstatat,
    [SYS_UNLINKAT]         = sys_unlinkat,
#ifdef __aarch64__
    [SYS_RENAME]           = sys_renameat2,
#endif
    [SYS_SYMLINKAT]        = sys_symlinkat,
    [SYS_READLINKAT]       = sys_readlinkat,
    [SYS_FCHMODAT]         = sys_fchmodat,
    [SYS_FCHOWNAT]         = sys_fchownat,
    [SYS_FACCESSAT]        = sys_faccessat,
    [SYS_UTIMENSAT]        = sys_utimensat,

    /* ---- x86_64 only: classic syscalls ---- */
#ifdef __NR_open
    [SYS_OPEN]             = sys_open,
    [SYS_STAT]             = sys_stat,
    [SYS_LSTAT]            = sys_stat,  /* lstat = stat for now (no hardlink distinction) */
    [SYS_PIPE]             = sys_pipe,
    [SYS_SELECT]           = sys_select,
    [SYS_DUP]              = sys_dup,
    [SYS_DUP2]             = sys_dup2,
#ifdef __NR_rmdir
    [SYS_RMDIR]            = sys_unlink,  /* rmdir = unlink for directories */
#endif
    [SYS_FORK]             = sys_fork_plain,
    [SYS_RENAME]           = sys_rename,
    [SYS_MKDIR]            = sys_mkdir,
#ifdef __NR_creat
    [SYS_CREAT]            = sys_create,  /* x86_64 only: creat(85) is separate from open(2) */
#endif
    [SYS_UNLINK]           = sys_unlink,
    [SYS_SYMLINK]          = sys_symlink,
    [SYS_READLINK]         = sys_readlink,
    [SYS_CHMOD]            = sys_chmod,
    [SYS_CHOWN]            = sys_chown,
    [SYS_ARCH_PRCTL]       = sys_arch_prctl,
    [SYS_EPOLL_WAIT]       = sys_epoll_wait,
#endif

    /* clone: handles flags + child_stack properly (musl uses clone) */
    [__NR_clone]           = sys_fork,
#ifdef __NR_vfork
    [__NR_vfork]           = sys_fork_plain,
#endif

    /* === Limnx-specific (512+) === */
    /* Legacy/convenience */
    [SYS_PUTS]             = sys_write,           /* old stdout-only write */
    [SYS_EXEC_OLD]         = sys_exec,            /* old fork+exec combo */
    [SYS_GETCHAR]          = sys_getchar,
    [SYS_READDIR]          = sys_readdir,
    [SYS_FMMAP]            = sys_fmmap,
    [SYS_MMAP2]            = sys_mmap2,
    [SYS_MMAP_FILE]        = sys_mmap_file,
    [SYS_MMAP_GUARD]       = sys_mmap_guard,

    /* Shared memory */
    [SYS_SHMGET]           = sys_shmget,
    [SYS_SHMAT]            = sys_shmat,
    [SYS_SHMDT]            = sys_shmdt,

    /* Environment */
    [SYS_GETENV]           = sys_getenv,
    [SYS_SETENV]           = sys_setenv,
    [SYS_ENVIRON]          = sys_environ,

    /* Agent infrastructure */
    [SYS_AGENT_REGISTER]   = sys_agent_register,
    [SYS_AGENT_LOOKUP]     = sys_agent_lookup,
    [SYS_AGENT_SEND]       = sys_agent_send,
    [SYS_AGENT_RECV]       = sys_agent_recv,

    /* Capability tokens */
    [SYS_TOKEN_CREATE]     = sys_token_create,
    [SYS_TOKEN_REVOKE]     = sys_token_revoke,
    [SYS_TOKEN_LIST]       = sys_token_list,
    [SYS_TOKEN_DELEGATE]   = sys_token_delegate,

    /* Agent namespaces */
    [SYS_NS_CREATE]        = sys_ns_create,
    [SYS_NS_JOIN]          = sys_ns_join,
    [SYS_NS_SETQUOTA]      = sys_ns_setquota,

    /* Inference service */
    [SYS_INFER_REGISTER]   = sys_infer_register,
    [SYS_INFER_REQUEST]    = sys_infer_request,
    [SYS_INFER_HEALTH]     = sys_infer_health,
    [SYS_INFER_ROUTE]      = sys_infer_route,
    [SYS_INFER_SET_POLICY] = sys_infer_set_policy,
    [SYS_INFER_QUEUE_STAT] = sys_infer_queue_stat,
    [SYS_INFER_CACHE_CTRL] = sys_infer_cache_ctrl,
    [SYS_INFER_SUBMIT]     = sys_infer_submit,
    [SYS_INFER_POLL]       = sys_infer_poll,
    [SYS_INFER_RESULT]     = sys_infer_result,
    [SYS_INFER_SWAP]       = sys_infer_swap,

    /* Task graph */
    [SYS_TASK_CREATE]      = sys_task_create,
    [SYS_TASK_DEPEND]      = sys_task_depend,
    [SYS_TASK_START]       = sys_task_start,
    [SYS_TASK_COMPLETE]    = sys_task_complete,
    [SYS_TASK_STATUS]      = sys_task_status,
    [SYS_TASK_WAIT]        = sys_task_wait,

    /* Supervisor trees */
    [SYS_SUPER_CREATE]     = sys_super_create,
    [SYS_SUPER_ADD]        = sys_super_add,
    [SYS_SUPER_SET_POLICY] = sys_super_set_policy,
    [SYS_SUPER_START]      = sys_super_start,
    [SYS_SUPER_LIST]       = sys_super_list,
    [SYS_SUPER_STOP]       = sys_super_stop,

    /* Pub/sub messaging */
    [SYS_TOPIC_CREATE]     = sys_topic_create,
    [SYS_TOPIC_SUB]        = sys_topic_subscribe,
    [SYS_TOPIC_PUB]        = sys_topic_publish,
    [SYS_TOPIC_RECV]       = sys_topic_recv,

    /* Unix domain sockets */
    [SYS_UNIX_SOCKET]      = sys_unix_socket,
    [SYS_UNIX_BIND]        = sys_unix_bind,
    [SYS_UNIX_LISTEN]      = sys_unix_listen,
    [SYS_UNIX_ACCEPT]      = sys_unix_accept,
    [SYS_UNIX_CONNECT]     = sys_unix_connect,

    /* TCP legacy */
    [SYS_TCP_SOCKET]       = sys_tcp_socket,
    [SYS_TCP_CONNECT]      = sys_tcp_connect,
    [SYS_TCP_LISTEN]       = sys_tcp_listen,
    [SYS_TCP_ACCEPT]       = sys_tcp_accept,
    [SYS_TCP_SEND]         = sys_tcp_send,
    [SYS_TCP_RECV]         = sys_tcp_recv,
    [SYS_TCP_CLOSE]        = sys_tcp_close,
    [SYS_TCP_SETOPT]       = sys_tcp_setopt,
    [SYS_TCP_TO_FD]        = sys_tcp_to_fd,

    /* Misc */
    [SYS_PROCINFO]         = sys_procinfo,
    [SYS_FSSTAT]           = sys_fsstat,
    [SYS_SWAP_STAT]        = sys_swap_stat,
    [SYS_SETAUDIT]         = sys_setaudit,
    [SYS_GETCAP]           = sys_getcap,
    [SYS_SETCAP]           = sys_setcap,
    [SYS_FUTEX_WAIT]       = sys_futex_wait,
    [SYS_FUTEX_WAKE]       = sys_futex_wake,
    [SYS_MKFIFO]           = sys_mkfifo,
    [SYS_TCSETPGRP]        = sys_tcsetpgrp,
    [SYS_TCGETPGRP]        = sys_tcgetpgrp,
    [SYS_GETPGID]          = sys_getpgid,
    [SYS_OPENPTY]          = sys_openpty,

    /* Accelerator */
    [SYS_ACCEL_SUBMIT]     = sys_accel_submit,
    [SYS_ACCEL_POLL]       = sys_accel_poll,
    [SYS_ACCEL_INFO]       = sys_accel_info,
};

/* Signal delivery is now per-CPU via percpu_t (GS-relative in asm).
 * We access it through percpu_get() in C code. */

int64_t syscall_dispatch(uint64_t num, uint64_t arg1, uint64_t arg2,
                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    if (num >= SYS_NR || !syscall_table[num]) {
        thread_t *et = thread_get_current();
        if (et && et->process && et->process->pid >= 3)
            serial_printf("[ENOSYS] pid=%lu sc=%lu\n", et->process->pid, num);
        return -ENOSYS;
    }

    /* Seccomp filtering: while a filter is active, standard syscalls
     * (< SECCOMP_LIMNX_BASE) need an allow bit. sys_seccomp itself only ever
     * narrows the filter. Limnx-specific syscalls are not filtered so
     * sandboxed services can keep using IPC; any process they create
     * inherits the filter. */
    thread_t *st = thread_get_current();
    if (st && st->process && st->process->seccomp_active &&
        num != SYS_EXIT && num != SYS_EXIT_GROUP && num != SYS_RT_SIGRETURN) {
        int allowed = 1;
        if (num < SECCOMP_LIMNX_BASE)
            allowed = !!(st->process->seccomp_bits[num / 64] & (1ULL << (num % 64)));
        if (!allowed) {
            if (st->process->seccomp_strict) {
                /* Terminate now: SIGKILL on the running thread would only
                 * take effect at the next reschedule, letting the process
                 * keep executing after the denied call. */
                serial_printf("[proc] Process %lu killed by seccomp (syscall %lu)\n",
                              st->process->pid, num);
                sys_exit((uint64_t)(128 + SIGKILL), 0, 0, 0, 0);
            }
            return -EACCES;
        }
    }

    int64_t result = syscall_table[num](arg1, arg2, arg3, arg4, arg5);

    /* Audit logging */
    if (st && st->process && st->process->audit_flags) {
        process_t *ap = st->process;
        if (ap->audit_flags & AUDIT_SYSCALL)
            serial_printf("[AUDIT pid=%lu uid=%u] syscall %lu = %ld\n",
                          ap->pid, ap->uid, num, result);
        if ((ap->audit_flags & AUDIT_SECURITY) &&
            (result == -EACCES || result == -EPERM))
            serial_printf("[AUDIT pid=%lu uid=%u] DENIED syscall %lu = %ld\n",
                          ap->pid, ap->uid, num, result);
        if ((ap->audit_flags & AUDIT_EXEC) &&
            (num == SYS_EXECVE || num == SYS_EXIT))
            serial_printf("[AUDIT pid=%lu uid=%u] %s = %ld\n",
                          ap->pid, ap->uid,
                          num == SYS_EXECVE ? "exec" : "exit", result);
        if ((ap->audit_flags & AUDIT_FILE) &&
            (num == SYS_OPENAT || num == SYS_UNLINKAT))
            serial_printf("[AUDIT pid=%lu uid=%u] file_op %lu = %ld\n",
                          ap->pid, ap->uid, num, result);
    }

    /* Check for pending signals after syscall */
    thread_t *t = thread_get_current();
    if (t && t->process) {
        process_t *proc = t->process;
        for (int sig = 1; sig < MAX_SIGNALS; sig++) {
            if (!(proc->pending_signals & (1U << sig))) continue;
            /* Skip masked (blocked) signals — they stay pending */
            if (proc->signal_mask & (1U << sig)) continue;
            proc->pending_signals &= ~(1U << sig);

            /* Re-pend from queue if there are duplicates queued */
            signal_queue_t *sq = &proc->sig_queue;
            for (int qi = 0; qi < sq->count; qi++) {
                int idx = (sq->head + qi) % SIG_QUEUE_SIZE;
                if (sq->signum[idx] == sig) {
                    /* Remove this entry by shifting */
                    for (int j = qi; j < sq->count - 1; j++) {
                        int from = (sq->head + j + 1) % SIG_QUEUE_SIZE;
                        int to = (sq->head + j) % SIG_QUEUE_SIZE;
                        sq->signum[to] = sq->signum[from];
                    }
                    sq->count--;
                    proc->pending_signals |= (1U << sig);  /* re-pend */
                    break;
                }
            }

            uint64_t handler = proc->sig_handlers[sig].sa_handler;
            if (handler == SIG_IGN) continue;
            if (handler == SIG_DFL) {
                /* SIGCHLD and SIGCONT default action is ignore */
                if (sig == SIGCHLD || sig == SIGCONT) continue;
                /* SIGTSTP/SIGTTIN/SIGTTOU default action is stop */
                if (sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                    t->state = THREAD_STOPPED;
                    sched_yield();
                    /* Resumed by SIGCONT — return to user */
                    break;
                }
                /* Default: kill — route through sys_exit for full cleanup
                 * (closes fds, TCP, agents, tokens, re-parents children, etc.) */
                serial_printf("[proc] Process %lu terminated (signal %d)\n",
                    proc->pid, sig);
                sys_exit((uint64_t)(128 + sig), 0, 0, 0, 0);
                /* sys_exit never returns */
            }

            /* User handler: set up signal frame */
            uint64_t orig_rip, orig_rsp, orig_rflags;
#if defined(__aarch64__)
            /* ARM64: read user context from per-thread exception frame.
             * Must be per-thread because a blocked thread may be preempted
             * by another SVC on the same CPU, clobbering the per-CPU pointer. */
            {
                uint64_t *ef = (uint64_t *)t->arch_frame;
                if (!ef) break;
                orig_rip    = ef[31];   /* elr_el1 */
                orig_rflags = ef[32];   /* spsr_el1 */
                orig_rsp    = ef[33];   /* sp_el0 */
            }
#else
            {
                uint64_t *kstack_top = (uint64_t *)(t->stack_base + t->stack_size);
                orig_rip = kstack_top[KSTACK_USER_RIP_OFF];
                orig_rsp = kstack_top[KSTACK_USER_RSP_OFF];
                orig_rflags = kstack_top[KSTACK_USER_FLAGS_OFF];
            }
#endif

            /* Build signal frame on user stack.
             * ARM64 needs full register save (34 regs × 8 = 272 bytes)
             * x86_64 only needs 4 values (rsp, rip, rflags, rax = 32 bytes) */
#if defined(__aarch64__)
            uint64_t frame_rsp = orig_rsp - (34 * 8);
#else
            uint64_t frame_rsp = orig_rsp - 32;
#endif
            frame_rsp &= ~0xFULL;  /* 16-byte align */

            /* Write frame via HHDM (user stack is mapped in process address space) */
            uint64_t *pte = vmm_get_pte(proc->cr3, frame_rsp);
            if (!pte || !(*pte & PTE_PRESENT)) break;  /* stack not mapped */

            /* Handle COW: if page is COW, copy it before writing signal frame */
            if (*pte & PTE_COW) {
                uint64_t old_phys = *pte & PTE_ADDR_MASK;
                uint64_t old_flags = *pte & ~PTE_ADDR_MASK;
                uint64_t clean = old_flags & ~(PTE_COW | PTE_WAS_WRITABLE);
                uint64_t writable = PTE_MAKE_WRITABLE(clean) | PTE_PRESENT;
                if (pmm_ref_get(old_phys) == 1) {
                    *pte = old_phys | writable;
                } else {
                    uint64_t new_phys = pmm_alloc_page();
                    if (new_phys == 0) break;
                    uint8_t *src = (uint8_t *)PHYS_TO_VIRT(old_phys);
                    uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(new_phys);
                    for (int i = 0; i < 4096; i++) dst[i] = src[i];
                    *pte = new_phys | writable;
                    pmm_ref_dec(old_phys);
                }
                invlpg_addr(frame_rsp & ~0xFFFULL);
                /* Re-read pte after COW */
                pte = vmm_get_pte(proc->cr3, frame_rsp);
                if (!pte || !(*pte & PTE_PRESENT)) break;
            }

            uint64_t stack_phys = (*pte & PTE_ADDR_MASK) + (frame_rsp & 0xFFF);
            uint64_t *frame = (uint64_t *)PHYS_TO_VIRT(stack_phys);

#if defined(__aarch64__)
            /* ARM64: save full exception frame (x0-x30, elr, spsr, sp) */
            {
                uint64_t *ef = (uint64_t *)t->arch_frame;
                for (int ri = 0; ri < 34; ri++)
                    frame[ri] = ef[ri];
                /* Overwrite x0 slot with original syscall result (not signal number) */
                frame[0] = (uint64_t)result;
            }
#else
            frame[0] = orig_rsp;
            frame[1] = orig_rip;
            frame[2] = orig_rflags;
            frame[3] = (uint64_t)result;
#endif

            if (proc->signal_depth < MAX_SIGNAL_DEPTH)
                proc->signal_frame_stack[proc->signal_depth++] = frame_rsp;
            else
                break;  /* too many nested signals, defer */

            /* SA_RESTART: save syscall info if result was -EINTR */
            if (result == -EINTR &&
                (proc->sig_handlers[sig].sa_flags & SA_RESTART)) {
                proc->restart_pending = 1;
                proc->restart_syscall_num = num;
                proc->restart_args[0] = arg1;
                proc->restart_args[1] = arg2;
                proc->restart_args[2] = arg3;
                proc->restart_args[3] = arg4;
                proc->restart_args[4] = arg5;
            } else {
                proc->restart_pending = 0;
            }

            /* Redirect SYSRET to handler via per-CPU data.
             * The asm stub overrides RCX (→RIP) and RSP after pops. */
            percpu_t *pc = percpu_get();
            pc->signal_handler_rip = handler;
            pc->signal_frame_rsp = frame_rsp;
            pc->signal_deliver_rdi = (uint64_t)sig;
            pc->signal_deliver_pending = 1;

            break;  /* deliver one signal at a time */
        }
    }

    return result;
}

void syscall_set_kernel_stack(uint64_t rsp) {
    arch_set_kernel_stack(rsp);
}

void syscall_init(void) {
    /* Set up BSP per-CPU data early so SWAPGS works from the first SYSCALL.
     * arch_syscall_init() will re-initialize this more fully later. */
    percpu_array[0].cpu_id = 0;
    percpu_array[0].signal_deliver_pending = 0;
    percpu_array[0].signal_deliver_rdi = 0;
    percpu_array[0].signal_handler_rip = 0;
    percpu_array[0].signal_frame_rsp = 0;
#if defined(__x86_64__)
    percpu_array[0].self = (uint64_t)&percpu_array[0];
#endif

    /* Delegate arch-specific setup (MSR programming, GS.base, etc.) */
    arch_syscall_init();

    pr_info("SYSCALL initialized\n");
}
