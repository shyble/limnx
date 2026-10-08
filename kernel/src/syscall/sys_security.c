#include "syscall/syscall_internal.h"
#include "sched/thread.h"
#include "ipc/cap_token.h"
#include "ipc/agent_ns.h"
#include "blk/limnfs.h"

int64_t sys_getuid(uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    return (int64_t)t->process->uid;
}

int64_t sys_setuid(uint64_t uid_arg, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;
    uint16_t new_uid = (uint16_t)uid_arg;

    if (proc->euid == 0) {
        /* Privileged: set all three IDs, drop caps if going non-root */
        proc->uid = new_uid;
        proc->euid = new_uid;
        proc->suid = new_uid;
        if (new_uid != 0)
            proc->capabilities = 0;  /* drop all caps */
    } else {
        /* Unprivileged: can only set euid to real uid or saved uid */
        if (new_uid != proc->uid && new_uid != proc->suid) {
            if (!(proc->capabilities & CAP_SETUID))
                return -EPERM;
        }
        proc->euid = new_uid;
    }
    return 0;
}

int64_t sys_getgid(uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    return (int64_t)t->process->gid;
}

int64_t sys_setgid(uint64_t gid_arg, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;
    uint16_t new_gid = (uint16_t)gid_arg;

    if (proc->euid == 0) {
        /* Privileged: set all three IDs */
        proc->gid = new_gid;
        proc->egid = new_gid;
        proc->sgid = new_gid;
    } else {
        /* Unprivileged: can only set egid to real gid or saved gid */
        if (new_gid != proc->gid && new_gid != proc->sgid) {
            if (!(proc->capabilities & CAP_SETUID))
                return -EPERM;
        }
        proc->egid = new_gid;
    }
    return 0;
}

int64_t sys_geteuid(uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    return (int64_t)t->process->euid;
}

int64_t sys_getegid(uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    return (int64_t)t->process->egid;
}

int64_t sys_getcap(uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    return (int64_t)t->process->capabilities;
}

int64_t sys_setcap(uint64_t pid_arg, uint64_t caps,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *caller = t->process;

    /* Only root or CAP_SYS_ADMIN can set capabilities */
    if (caller->euid != 0 && !(caller->capabilities & CAP_SYS_ADMIN))
        return -EPERM;

    /* Cannot grant caps the caller doesn't have */
    if (caps & ~caller->capabilities)
        return -EPERM;

    uint64_t pid = pid_arg == 0 ? caller->pid : pid_arg;
    process_t *target = process_lookup(pid);
    if (!target) return -ESRCH;

    target->capabilities = (uint32_t)caps;
    return 0;
}

int64_t sys_getrlimit(uint64_t resource, uint64_t ptr,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (validate_user_ptr(ptr, sizeof(rlimit_t)) != 0)
        return -EFAULT;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;
    rlimit_t *rl = (rlimit_t *)ptr;

    switch (resource) {
    case RLIMIT_MEM:
        rl->current = proc->used_mem_pages;
        rl->max = proc->rlimit_mem_pages;
        return 0;
    case RLIMIT_CPU:
        rl->current = proc->main_thread ? proc->main_thread->ticks_used : 0;
        rl->max = proc->rlimit_cpu_ticks;
        return 0;
    case RLIMIT_NFDS:
        rl->current = (uint64_t)count_open_fds(proc);
        rl->max = (uint64_t)proc->rlimit_nfds;
        return 0;
    default:
        return -EINVAL;
    }
}

int64_t sys_setrlimit(uint64_t resource, uint64_t ptr,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (validate_user_ptr(ptr, sizeof(rlimit_t)) != 0)
        return -EFAULT;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;

    /* Only root or CAP_SYS_ADMIN */
    if (proc->euid != 0 && !(proc->capabilities & CAP_SYS_ADMIN))
        return -EPERM;

    const rlimit_t *rl = (const rlimit_t *)ptr;
    switch (resource) {
    case RLIMIT_MEM:
        proc->rlimit_mem_pages = rl->max;
        return 0;
    case RLIMIT_CPU:
        proc->rlimit_cpu_ticks = rl->max;
        return 0;
    case RLIMIT_NFDS:
        proc->rlimit_nfds = (uint32_t)rl->max;
        return 0;
    default:
        return -EINVAL;
    }
}

/* seccomp(mask, strict, mask_hi, bitmap_ptr):
 *   bitmap_ptr == 0: legacy form, mask/mask_hi allow syscalls 0-127.
 *   bitmap_ptr != 0: user array of SECCOMP_WORDS words allowing 0-511;
 *                    mask/mask_hi are ignored.
 * Standard syscalls without an allow bit are denied. Limnx syscalls
 * (>= SECCOMP_LIMNX_BASE) are not filtered. */
int64_t sys_seccomp(uint64_t mask, uint64_t strict,
                             uint64_t mask_hi, uint64_t bitmap_ptr, uint64_t a5) {
    (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;

    uint64_t bits[SECCOMP_WORDS];
    for (int i = 0; i < SECCOMP_WORDS; i++)
        bits[i] = 0;
    if (bitmap_ptr) {
        if (validate_user_ptr(bitmap_ptr, sizeof(bits)) != 0)
            return -EFAULT;
        const uint64_t *ubits = (const uint64_t *)bitmap_ptr;
        for (int i = 0; i < SECCOMP_WORDS; i++)
            bits[i] = ubits[i];
    } else {
        bits[0] = mask;
        bits[1] = mask_hi;
    }

    /* A filter can only ever be narrowed. An explicit active flag is used
     * because an all-zero bitmap is a valid (deny-everything) filter, not
     * "no filter". */
    for (int i = 0; i < SECCOMP_WORDS; i++) {
        if (proc->seccomp_active)
            proc->seccomp_bits[i] &= bits[i];
        else
            proc->seccomp_bits[i] = bits[i];
    }
    proc->seccomp_active = 1;
    if (strict)
        proc->seccomp_strict = 1;
    return 0;
}

int64_t sys_setaudit(uint64_t pid_arg, uint64_t flags,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *caller = t->process;

    /* Only root or CAP_SYS_ADMIN */
    if (caller->euid != 0 && !(caller->capabilities & CAP_SYS_ADMIN))
        return -EPERM;

    uint64_t pid = pid_arg == 0 ? caller->pid : pid_arg;
    process_t *target = process_lookup(pid);
    if (!target) return -ESRCH;

    target->audit_flags = (uint8_t)flags;
    return 0;
}

int64_t sys_token_create(uint64_t perms, uint64_t target_pid,
                                uint64_t resource_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    char resource[TOKEN_PATH_MAX];
    resource[0] = '\0';
    if (resource_ptr != 0) {
        if (copy_string_from_user((const char *)resource_ptr, resource, TOKEN_PATH_MAX) != 0)
            return -EFAULT;
    }

    return cap_token_create(proc->pid, proc->capabilities,
                            (uint32_t)perms, target_pid, resource);
}

int64_t sys_token_revoke(uint64_t token_id, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    return cap_token_revoke((uint32_t)token_id, proc->pid);
}

int64_t sys_token_list(uint64_t buf_ptr, uint64_t max_count,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    if (max_count == 0 || buf_ptr == 0) return 0;
    if (max_count > 32) max_count = 32;

    if (validate_user_ptr(buf_ptr, max_count * sizeof(token_info_t)) != 0)
        return -EFAULT;

    return cap_token_list(proc->pid, (token_info_t *)buf_ptr, (int)max_count);
}

int64_t sys_ns_create(uint64_t name_ptr, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    /* Only root or CAP_SYS_ADMIN can create namespaces */
    if (proc->euid != 0 && !(proc->capabilities & CAP_SYS_ADMIN))
        return -EPERM;

    char name[NS_NAME_MAX];
    name[0] = '\0';
    if (name_ptr != 0) {
        if (copy_string_from_user((const char *)name_ptr, name, NS_NAME_MAX) != 0)
            return -EFAULT;
    }

    return agent_ns_create(name, proc->pid);
}

int64_t sys_ns_join(uint64_t ns_id, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    int ret = agent_ns_join((uint32_t)ns_id, proc->pid, proc->euid);
    if (ret == 0)
        proc->ns_id = (uint32_t)ns_id;
    return ret;
}

int64_t sys_token_delegate(uint64_t parent_id, uint64_t target_pid,
                                    uint64_t perms, uint64_t resource_ptr,
                                    uint64_t a5) {
    (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;

    char resource[TOKEN_PATH_MAX];
    resource[0] = '\0';
    if (resource_ptr) {
        if (copy_string_from_user((const char *)resource_ptr, resource, TOKEN_PATH_MAX) != 0)
            return -EFAULT;
    }

    return cap_token_delegate((uint32_t)parent_id, t->process->pid,
                               target_pid, (uint32_t)perms, resource);
}

int64_t sys_ns_setquota(uint64_t ns_id, uint64_t resource,
                                 uint64_t limit, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    return agent_ns_set_quota((uint32_t)ns_id, (uint32_t)resource, (uint32_t)limit,
                               t->process->pid, t->process->euid);
}

/* --- New Stage 96 syscalls --- */

int64_t sys_chown(uint64_t path_ptr, uint64_t uid_arg, uint64_t gid_arg,
                           uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    int idx = vfs_resolve_path(path);
    if (idx < 0) return -ENOENT;

    uint16_t new_uid = (uint16_t)uid_arg;
    uint16_t new_gid = (uint16_t)gid_arg;

    /* Only root (euid==0) or CAP_CHOWN can change owner */
    if (proc->euid != 0 && !(proc->capabilities & CAP_CHOWN))
        return -EPERM;

    return vfs_chown(idx, new_uid, new_gid);
}

int64_t sys_fchown(uint64_t fd, uint64_t uid_arg, uint64_t gid_arg,
                            uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (fd >= MAX_FDS) return -EBADF;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    fd_entry_t *entry = &proc->fd_table[fd];
    if (!entry->node) return -EBADF;

    /* Only root or CAP_CHOWN */
    if (proc->euid != 0 && !(proc->capabilities & CAP_CHOWN))
        return -EPERM;

    int idx = vfs_node_index(entry->node);
    if (idx < 0) return -EBADF;

    return vfs_chown(idx, (uint16_t)uid_arg, (uint16_t)gid_arg);
}

int64_t sys_umask(uint64_t new_mask, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;

    uint16_t old = proc->umask;
    proc->umask = (uint16_t)(new_mask & 0777);
    return (int64_t)old;
}

int64_t sys_getgroups(uint64_t buf_ptr, uint64_t max_count,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;

    if (max_count == 0)
        return (int64_t)proc->ngroups;  /* query count */

    if (validate_user_ptr(buf_ptr, max_count * sizeof(uint16_t)) != 0)
        return -EFAULT;

    uint16_t *out = (uint16_t *)buf_ptr;
    int n = proc->ngroups;
    if ((uint64_t)n > max_count) n = (int)max_count;
    for (int i = 0; i < n; i++)
        out[i] = proc->groups[i];

    return (int64_t)n;
}

int64_t sys_setgroups(uint64_t groups_ptr, uint64_t count,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;
    process_t *proc = t->process;

    /* Only root or CAP_SETUID */
    if (proc->euid != 0 && !(proc->capabilities & CAP_SETUID))
        return -EPERM;

    if (count > MAX_SUPPL_GROUPS)
        return -EINVAL;

    if (count > 0) {
        if (validate_user_ptr(groups_ptr, count * sizeof(uint16_t)) != 0)
            return -EFAULT;
        const uint16_t *in = (const uint16_t *)groups_ptr;
        for (uint64_t i = 0; i < count; i++)
            proc->groups[i] = in[i];
    }
    proc->ngroups = (uint8_t)count;
    return 0;
}
