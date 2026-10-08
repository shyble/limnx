#include "syscall/syscall_internal.h"
#include "sched/sched.h"
#include "sched/thread.h"
#include "mm/vmm.h"
#include "mm/pmm.h"
#include "pty/pty.h"
#include "ipc/unix_sock.h"
#include "ipc/eventfd.h"
#include "ipc/epoll.h"
#include "ipc/uring.h"
#include "ipc/cap_token.h"
#include "blk/limnfs.h"
#include "net/tcp.h"
#include "arch/serial.h"
#include "limnx/stat.h"

/* Fill a Linux-compatible struct stat from a VFS node */
static void fill_linux_stat(struct linux_stat *ls, vfs_node_t *node, int node_idx) {
    /* Zero entire struct first */
    uint8_t *p = (uint8_t *)ls;
    for (unsigned i = 0; i < sizeof(struct linux_stat); i++) p[i] = 0;

    ls->st_ino = (uint64_t)(node_idx + 1);  /* inode = VFS index + 1 (0 reserved) */
    ls->st_nlink = 1;
    ls->st_size = (int64_t)node->size;
    ls->st_uid = (uint32_t)node->uid;
    ls->st_gid = (uint32_t)node->gid;
    ls->st_blksize = 4096;
    ls->st_blocks = (int64_t)((node->size + 511) / 512);

    /* File type + permission mode */
    uint32_t ftype = 0;
    switch (node->type) {
        case VFS_FILE:      ftype = S_IFREG; break;
        case VFS_DIRECTORY: ftype = S_IFDIR; break;
        case VFS_SYMLINK:   ftype = S_IFLNK; break;
        case VFS_FIFO:      ftype = S_IFIFO; break;
        case VFS_DEVICE:    ftype = S_IFCHR; break;
        default:            ftype = S_IFREG; break;
    }
    ls->st_mode = ftype | (uint32_t)(node->mode & 0xFFF);
}

int64_t sys_open(uint64_t path_ptr, uint64_t flags,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;
    resolve_user_path(proc, raw_path, path);

    /* Refresh /proc/<pid>/ content on open */
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
        path[3] == 'o' && path[4] == 'c' && path[5] == '/') {
        /* Extract PID from /proc/<pid>/... */
        uint64_t ppid = 0;
        const char *dp = path + 6;
        while (*dp >= '0' && *dp <= '9') {
            ppid = ppid * 10 + (*dp - '0');
            dp++;
        }
        if (ppid > 0) {
            extern void vfs_procfs_refresh(uint64_t pid);
            vfs_procfs_refresh(ppid);
        }
    }

    /* Find the file in VFS */
    int node_idx = vfs_open(path);

    /* O_CREAT: create file if it doesn't exist */
    if (node_idx < 0 && (flags & O_CREAT)) {
        /* Check write permission on parent directory */
        char parent_path[MAX_PATH], base_name[MAX_PATH];
        vfs_path_split(path, parent_path, base_name);
        int parent_idx = vfs_resolve_path(parent_path);
        if (parent_idx >= 0) {
            vfs_node_t *parent_node = vfs_get_node(parent_idx);
            if (parent_node && check_file_perm(proc, parent_node, O_WRONLY) != 0)
                return -EACCES;
        }

        node_idx = vfs_create(path);
        if (node_idx < 0)
            return -1;

        /* Set ownership to creator and apply umask */
        vfs_node_t *new_node = vfs_get_node(node_idx);
        if (new_node) {
            new_node->uid = proc->euid;
            new_node->gid = proc->egid;
            new_node->mode = 0666 & ~proc->umask;
        }
    }

    if (node_idx < 0)
        return -1;

    /* Capability checks (with token fallback) */
    {
        uint8_t acc = (uint8_t)(flags & O_ACCMODE);
        if ((acc == O_RDONLY || acc == O_RDWR) &&
            !(proc->capabilities & CAP_FS_READ) &&
            !cap_token_check(proc->pid, CAP_FS_READ, path))
            return -EACCES;
        if ((acc == O_WRONLY || acc == O_RDWR) &&
            !(proc->capabilities & CAP_FS_WRITE) &&
            !cap_token_check(proc->pid, CAP_FS_WRITE, path))
            return -EACCES;
    }

    /* Permission checks */
    vfs_node_t *file_node = vfs_get_node(node_idx);
    if (file_node) {
        uint8_t acc = (uint8_t)(flags & O_ACCMODE);
        /* VFS_FLAG_WRITABLE gate applies to all users including root */
        if ((acc == O_WRONLY || acc == O_RDWR) &&
            !(file_node->flags & VFS_FLAG_WRITABLE))
            return -EACCES;
        int perm = check_file_perm(proc, file_node, acc);
        if (perm != 0)
            return perm;
    }

    /* fd limit check */
    if (proc->rlimit_nfds > 0 &&
        (uint32_t)count_open_fds(proc) >= proc->rlimit_nfds)
        return -EMFILE;

    /* O_TRUNC: truncate to zero on open */
    if (flags & O_TRUNC) {
        vfs_truncate_node(node_idx, 0);
    }

    /* FIFO: connect to pipe */
    vfs_node_t *fnode = vfs_get_node(node_idx);
    if (fnode && fnode->type == VFS_FIFO) {
        extern pipe_t pipes[];
        extern void pipe_lock_acquire(uint64_t *);
        extern void pipe_unlock_release(uint64_t);

        pipe_t *pp = (pipe_t *)fnode->data;
        if (!pp) {
            /* First opener: allocate a pipe */
            uint64_t pflags;
            pipe_lock_acquire(&pflags);
            int slot = -1;
            for (int i = 0; i < 8; i++) {
                if (!pipes[i].used) { slot = i; break; }
            }
            if (slot < 0) { pipe_unlock_release(pflags); return -ENOMEM; }
            pp = &pipes[slot];
            pp->read_pos = 0;
            pp->write_pos = 0;
            pp->count = 0;
            pp->closed_read = 0;
            pp->closed_write = 0;
            pp->used = 1;
            pp->read_refs = 0;
            pp->write_refs = 0;
            fnode->data = (uint8_t *)pp;
            pipe_unlock_release(pflags);
        }

        uint8_t acc = (uint8_t)(flags & O_ACCMODE);
        int is_write = (acc == O_WRONLY || acc == O_RDWR);
        int is_read = (acc == O_RDONLY || acc == O_RDWR);

        for (int fd = 0; fd < MAX_FDS; fd++) {
            if (fd_is_free(&proc->fd_table[fd])) {
                proc->fd_table[fd].node = fnode;
                proc->fd_table[fd].offset = 0;
                proc->fd_table[fd].pipe = (void *)pp;
                proc->fd_table[fd].pipe_write = is_write ? 1 : 0;
                proc->fd_table[fd].pty = NULL;
                proc->fd_table[fd].pty_is_master = 0;
                proc->fd_table[fd].unix_sock = NULL;
                proc->fd_table[fd].eventfd = NULL;
                proc->fd_table[fd].epoll = NULL;
                proc->fd_table[fd].uring = NULL;
                proc->fd_table[fd].open_flags = (uint8_t)(flags & O_ACCMODE);
                proc->fd_table[fd].fd_flags = 0;
                if (is_read) pp->read_refs++;
                if (is_write) pp->write_refs++;
                return fd;
            }
        }
        return -1;
    }

    /* Store open flags (access mode + O_APPEND + O_NONBLOCK etc.) */
    uint32_t stored_flags = (uint32_t)(flags & (O_ACCMODE | O_APPEND | O_NONBLOCK));

    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (fd_is_free(&proc->fd_table[fd])) {
            proc->fd_table[fd].node = fnode;
            proc->fd_table[fd].offset = 0;
            proc->fd_table[fd].pipe = NULL;
            proc->fd_table[fd].pipe_write = 0;
            proc->fd_table[fd].pty = NULL;
            proc->fd_table[fd].pty_is_master = 0;
            proc->fd_table[fd].unix_sock = NULL;
            proc->fd_table[fd].eventfd = NULL;
            proc->fd_table[fd].epoll = NULL;
            proc->fd_table[fd].uring = NULL;
            proc->fd_table[fd].open_flags = stored_flags;
            proc->fd_table[fd].fd_flags = 0;
            return fd;
        }
    }

    return -1;  /* no free fd */
}

int64_t sys_read(uint64_t fd, uint64_t buf_ptr, uint64_t len,
                          uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    if (fd >= MAX_FDS)
        return -1;
    if (len == 0)
        return 0;
    if (validate_user_ptr(buf_ptr, len) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    fd_entry_t *entry = &proc->fd_table[fd];

    /* Device read */
    if (entry->node && entry->node->type == VFS_DEVICE) {
        int minor = entry->node->disk_inode;
        uint8_t *dst = (uint8_t *)buf_ptr;
        if (minor == DEV_NULL) return 0;  /* EOF */
        if (minor == DEV_ZERO) {
            for (uint64_t i = 0; i < len; i++) dst[i] = 0;
            return (int64_t)len;
        }
        if (minor == DEV_URANDOM) {
            static uint64_t seed = 0x12345678DEADBEEFULL;
            for (uint64_t i = 0; i < len; i++) {
                seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                dst[i] = (uint8_t)(seed & 0xFF);
            }
            return (int64_t)len;
        }
        if (minor == DEV_TTY) {
            /* /dev/tty reads from the process's stdin (fd 0) */
            return sys_read(0, buf_ptr, len, 0, 0);
        }
        return -ENODEV;
    }

    /* Pipe read */
    if (entry->pipe != NULL) {
        pipe_t *pp = (pipe_t *)entry->pipe;
        uint8_t *dst = (uint8_t *)buf_ptr;
        uint64_t total = 0;
        while (total < len) {
            uint64_t pflags;
            pipe_lock_acquire(&pflags);
            if (pp->count > 0) {
                dst[total] = pp->buf[pp->read_pos];
                pp->read_pos = (pp->read_pos + 1) % PIPE_BUF_SIZE;
                pp->count--;
                pipe_unlock_release(pflags);
                total++;
            } else if (pp->closed_write) {
                pipe_unlock_release(pflags);
                break;  /* EOF — writer closed */
            } else {
                pipe_unlock_release(pflags);
                if (total > 0) break;  /* return what we have */
                if (entry->fd_flags & 0x02)  /* O_NONBLOCK */
                    return -EAGAIN;
                if (proc->pending_signals & ~proc->signal_mask)
                    return -EINTR;
                sched_yield();
            }
        }
        return (int64_t)total;
    }

    /* PTY read */
    if (entry->pty != NULL) {
        int pty_idx = pty_index((pty_t *)entry->pty);
        if (pty_idx < 0) return -1;
        int nonblock = (entry->fd_flags & 0x02) ? 1 : 0;
        if (entry->pty_is_master)
            return pty_master_read(pty_idx, (uint8_t *)buf_ptr, (uint32_t)len);
        else
            return pty_slave_read(pty_idx, (uint8_t *)buf_ptr, (uint32_t)len, nonblock);
    }

    /* Unix socket read */
    if (entry->unix_sock != NULL) {
        int nonblock = (entry->fd_flags & 0x02) ? 1 : 0;
        return unix_sock_recv((unix_sock_t *)entry->unix_sock,
                              (uint8_t *)buf_ptr, (uint32_t)len, nonblock);
    }

    /* Eventfd read */
    if (entry->eventfd != NULL) {
        if (len < 8) return -1;
        int nonblock = (entry->fd_flags & 0x02) ? 1 : 0;
        int efd_idx = eventfd_index((const eventfd_t *)entry->eventfd);
        if (efd_idx < 0) return -1;
        return eventfd_read(efd_idx, (uint64_t *)buf_ptr, nonblock);
    }

    /* epoll/uring fds are not readable */
    if (entry->epoll != NULL || entry->uring != NULL)
        return -EINVAL;

    if (entry->node == NULL)
        return -1;

    /* Reject read on write-only fd */
    if ((entry->open_flags & O_ACCMODE) == O_WRONLY)
        return -1;

    vfs_node_t *node = entry->node;
    int node_idx = vfs_node_index(node);
    if (node_idx < 0)
        return -1;

    int64_t n = vfs_read(node_idx, entry->offset, (uint8_t *)buf_ptr, len);
    if (n > 0)
        entry->offset += (uint64_t)n;
    return n;
}

/* Shared fd close helper — closes any IPC resource held by an fd entry
 * and resets the entry to empty. Used by sys_close, sys_exit, dup2. */
void fd_close(fd_entry_t *entry) {
    if (entry->pipe != NULL) {
        uint64_t pflags;
        pipe_lock_acquire(&pflags);
        pipe_t *pp = (pipe_t *)entry->pipe;
        if (entry->pipe_write) {
            if (pp->write_refs > 0) pp->write_refs--;
            if (pp->write_refs == 0) pp->closed_write = 1;
        } else {
            if (pp->read_refs > 0) pp->read_refs--;
            if (pp->read_refs == 0) pp->closed_read = 1;
        }
        if (pp->closed_read && pp->closed_write) pp->used = 0;
        pipe_unlock_release(pflags);
        entry->pipe = NULL;
        entry->pipe_write = 0;
    }
    if (entry->pty != NULL) {
        int pty_idx = pty_index((pty_t *)entry->pty);
        if (pty_idx >= 0) {
            if (entry->pty_is_master)
                pty_close_master(pty_idx);
            else
                pty_close_slave(pty_idx);
        }
        entry->pty = NULL;
        entry->pty_is_master = 0;
    }
    if (entry->unix_sock != NULL) {
        unix_sock_close((unix_sock_t *)entry->unix_sock);
        entry->unix_sock = NULL;
    }
    if (entry->eventfd != NULL) {
        int ei = eventfd_index((const eventfd_t *)entry->eventfd);
        if (ei >= 0) eventfd_close(ei);
        entry->eventfd = NULL;
    }
    if (entry->epoll != NULL) {
        int ep_idx = epoll_index((epoll_instance_t *)entry->epoll);
        if (ep_idx >= 0) epoll_close(ep_idx);
        entry->epoll = NULL;
    }
    if (entry->uring != NULL) {
        int ur_idx = uring_index((uring_instance_t *)entry->uring);
        if (ur_idx >= 0) uring_close(ur_idx);
        entry->uring = NULL;
    }
    if (entry->tcp_conn_idx >= 0)
        entry->tcp_conn_idx = -1;
    entry->node = NULL;
    entry->offset = 0;
    entry->open_flags = 0;
    entry->fd_flags = 0;
}

int64_t sys_close(uint64_t fd, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    if (fd >= MAX_FDS)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    fd_entry_t *entry = &proc->fd_table[fd];
    if (fd_is_free(entry))
        return -1;

    fd_close(entry);
    return 0;
}

/*
 * Linux *at() syscall wrappers — take (dirfd, path, ...) instead of (path, ...).
 * We ignore dirfd (assume AT_FDCWD) since we always resolve from cwd.
 * These are needed because ARM64 generic table only has *at() variants,
 * and musl on x86_64 also prefers *at() for newer programs.
 */
int64_t sys_fstatat(uint64_t dirfd, uint64_t path_ptr,
                             uint64_t stat_ptr, uint64_t flags, uint64_t a5) {
    (void)a5;

    char raw_path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;
    if (validate_user_ptr(stat_ptr, sizeof(struct linux_stat)) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t ? t->process : NULL;
    if (!proc) return -1;

    char path[MAX_PATH];
    if (raw_path[0] == '/') {
        /* Absolute path — use as-is */
        int i = 0;
        while (raw_path[i] && i < MAX_PATH - 1) { path[i] = raw_path[i]; i++; }
        path[i] = '\0';
    } else if ((int64_t)dirfd == -100) {
        /* AT_FDCWD (-100) — resolve relative to cwd */
        resolve_user_path(proc, raw_path, path);
    } else if (dirfd < MAX_FDS && proc->fd_table[dirfd].node) {
        /* Resolve relative to directory fd */
        vfs_node_t *dir = proc->fd_table[dirfd].node;
        int dir_idx = vfs_node_index(dir);
        /* Build absolute path: walk dir node to root + append raw_path */
        int chain[64];
        int depth = 0;
        for (int n = dir_idx; n > 0 && depth < 64; n = vfs_get_node(n)->parent)
            chain[depth++] = n;
        int pos = 0;
        for (int d = depth - 1; d >= 0 && pos < MAX_PATH - 2; d--) {
            path[pos++] = '/';
            const char *nm = vfs_get_node(chain[d])->name;
            for (int j = 0; nm[j] && pos < MAX_PATH - 1; j++)
                path[pos++] = nm[j];
        }
        if (pos == 0) path[pos++] = '/';
        /* Append / + relative path */
        if (pos < MAX_PATH - 1 && path[pos - 1] != '/') path[pos++] = '/';
        for (int j = 0; raw_path[j] && pos < MAX_PATH - 1; j++)
            path[pos++] = raw_path[j];
        path[pos] = '\0';
    } else {
        return -EBADF;
    }

    int idx = vfs_resolve_path(path);
    if (idx < 0) return -ENOENT;
    vfs_node_t *node = vfs_get_node(idx);
    if (!node) return -ENOENT;

    /* Follow symlink (stat follows by default, lstat doesn't) */
    if (node->type == VFS_SYMLINK && node->data) {
        char target[256];
        uint64_t tlen = node->size < 255 ? node->size : 255;
        for (uint64_t i = 0; i < tlen; i++) target[i] = (char)node->data[i];
        target[tlen] = '\0';
        int tidx = vfs_resolve_path(target);
        if (tidx >= 0) {
            idx = tidx;
            node = vfs_get_node(idx);
            if (!node) return -ENOENT;
        }
    }

    struct linux_stat ls;
    fill_linux_stat(&ls, node, idx);
    uint8_t *dst = (uint8_t *)stat_ptr;
    const uint8_t *src = (const uint8_t *)&ls;
    for (uint64_t i = 0; i < sizeof(struct linux_stat); i++)
        dst[i] = src[i];
    return 0;
}

int64_t sys_openat(uint64_t dirfd, uint64_t path_ptr,
                            uint64_t flags, uint64_t mode, uint64_t a5) {
    (void)dirfd; (void)mode; (void)a5;
    return sys_open(path_ptr, flags, 0, 0, 0);
}

int64_t sys_mkdirat(uint64_t dirfd, uint64_t path_ptr,
                             uint64_t mode, uint64_t a4, uint64_t a5) {
    (void)dirfd; (void)mode; (void)a4; (void)a5;
    return sys_mkdir(path_ptr, 0, 0, 0, 0);
}

int64_t sys_unlinkat(uint64_t dirfd, uint64_t path_ptr,
                              uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)dirfd; (void)a4; (void)a5;
    /* AT_REMOVEDIR (0x200): behave like rmdir instead of unlink.
     * Our vfs_delete handles both files and directories, so just pass through. */
    (void)flags;
    return sys_unlink(path_ptr, 0, 0, 0, 0);
}

int64_t sys_symlinkat(uint64_t target_ptr, uint64_t dirfd,
                               uint64_t path_ptr, uint64_t a4, uint64_t a5) {
    (void)dirfd; (void)a4; (void)a5;
    return sys_symlink(target_ptr, path_ptr, 0, 0, 0);
}

int64_t sys_readlinkat(uint64_t dirfd, uint64_t path_ptr,
                                uint64_t buf_ptr, uint64_t bufsize, uint64_t a5) {
    (void)dirfd; (void)a5;
    return sys_readlink(path_ptr, buf_ptr, bufsize, 0, 0);
}

int64_t sys_fchmodat(uint64_t dirfd, uint64_t path_ptr,
                              uint64_t mode, uint64_t a4, uint64_t a5) {
    (void)dirfd; (void)a4; (void)a5;
    return sys_chmod(path_ptr, mode, 0, 0, 0);
}

int64_t sys_fchownat(uint64_t dirfd, uint64_t path_ptr,
                              uint64_t uid, uint64_t gid, uint64_t flags) {
    (void)dirfd; (void)flags;
    return sys_chown(path_ptr, uid, gid, 0, 0);
}

int64_t sys_faccessat(uint64_t dirfd, uint64_t path_ptr,
                               uint64_t mode, uint64_t flags, uint64_t a5) {
    (void)dirfd; (void)flags; (void)a5;
    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;
    thread_t *t = thread_get_current();
    process_t *proc = t ? t->process : NULL;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);
    int idx = vfs_resolve_path(path);
    if (idx < 0)
        return -ENOENT;
    /* F_OK (0) only checks existence; R_OK/W_OK/X_OK map to rwx bits */
    int mask = (int)(mode & (VFS_PERM_READ | VFS_PERM_WRITE | VFS_PERM_EXEC));
    if (mask == 0)
        return 0;
    vfs_node_t *node = vfs_get_node(idx);
    if (!node)
        return -ENOENT;
    return check_node_access_real(proc, node, mask);
}

int64_t sys_stat(uint64_t path_ptr, uint64_t stat_ptr,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;
    if (validate_user_ptr(stat_ptr, sizeof(struct linux_stat)) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    int idx = vfs_resolve_path(path);
    if (idx < 0) return -ENOENT;
    vfs_node_t *node = vfs_get_node(idx);
    if (!node) return -ENOENT;

    /* Follow symlink (stat always follows, lstat doesn't — lstat is separate) */
    if (node->type == VFS_SYMLINK && node->data) {
        char target[256];
        uint64_t tlen = node->size < 255 ? node->size : 255;
        for (uint64_t i = 0; i < tlen; i++) target[i] = (char)node->data[i];
        target[tlen] = '\0';
        int tidx = vfs_resolve_path(target);
        if (tidx >= 0) {
            idx = tidx;
            node = vfs_get_node(idx);
            if (!node) return -ENOENT;
        }
    }

    struct linux_stat ls;
    fill_linux_stat(&ls, node, idx);

    /* Copy to user buffer */
    uint8_t *dst = (uint8_t *)stat_ptr;
    const uint8_t *src = (const uint8_t *)&ls;
    for (uint64_t i = 0; i < sizeof(struct linux_stat); i++)
        dst[i] = src[i];

    return 0;
}

int64_t sys_fwrite(uint64_t fd, uint64_t buf_ptr, uint64_t len,
                            uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    if (fd >= MAX_FDS)
        return -1;
    if (len == 0)
        return 0;
    if (validate_user_ptr(buf_ptr, len) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    fd_entry_t *entry = &proc->fd_table[fd];

    /* Device write */
    if (entry->node && entry->node->type == VFS_DEVICE) {
        int minor = entry->node->disk_inode;
        if (minor == DEV_NULL) return (int64_t)len;  /* discard */
        if (minor == DEV_TTY) return sys_fwrite(1, buf_ptr, len, 0, 0);
        return -ENODEV;
    }

    /* Pipe write */
    if (entry->pipe != NULL) {
        pipe_t *pp = (pipe_t *)entry->pipe;
        const uint8_t *src = (const uint8_t *)buf_ptr;
        uint64_t total = 0;
        while (total < len) {
            uint64_t pflags;
            pipe_lock_acquire(&pflags);
            if (pp->closed_read) {
                pipe_unlock_release(pflags);
                return total > 0 ? (int64_t)total : -1;
            }
            if (pp->count < PIPE_BUF_SIZE) {
                pp->buf[pp->write_pos] = src[total];
                pp->write_pos = (pp->write_pos + 1) % PIPE_BUF_SIZE;
                pp->count++;
                pipe_unlock_release(pflags);
                total++;
            } else {
                pipe_unlock_release(pflags);
                if (entry->fd_flags & 0x02)  /* O_NONBLOCK */
                    return total > 0 ? (int64_t)total : -1;
                if (proc->pending_signals & ~proc->signal_mask)
                    return total > 0 ? (int64_t)total : -EINTR;
                sched_yield();
            }
        }
        return (int64_t)total;
    }

    /* PTY write */
    if (entry->pty != NULL) {
        int pty_idx = pty_index((pty_t *)entry->pty);
        if (pty_idx < 0) return -1;
        if (entry->pty_is_master)
            return pty_master_write(pty_idx, (const uint8_t *)buf_ptr, (uint32_t)len);
        else
            return pty_slave_write(pty_idx, (const uint8_t *)buf_ptr, (uint32_t)len);
    }

    /* Unix socket write */
    if (entry->unix_sock != NULL) {
        int nonblock = (entry->fd_flags & 0x02) ? 1 : 0;
        return unix_sock_send((unix_sock_t *)entry->unix_sock,
                              (const uint8_t *)buf_ptr, (uint32_t)len, nonblock);
    }

    /* Eventfd write */
    if (entry->eventfd != NULL) {
        if (len < 8) return -1;
        int efd_idx = eventfd_index((const eventfd_t *)entry->eventfd);
        if (efd_idx < 0) return -1;
        return eventfd_write(efd_idx, *(const uint64_t *)buf_ptr);
    }

    /* epoll/uring fds are not writable */
    if (entry->epoll != NULL || entry->uring != NULL)
        return -EINVAL;

    if (entry->node == NULL)
        return -1;

    /* Reject write on read-only fd */
    if ((entry->open_flags & O_ACCMODE) == O_RDONLY)
        return -1;

    vfs_node_t *node = entry->node;
    int node_idx = vfs_node_index(node);
    if (node_idx < 0)
        return -1;

    /* O_APPEND: always write at end */
    if (entry->open_flags & O_APPEND)
        entry->offset = node->size;

    int64_t written = vfs_write(node_idx, entry->offset,
                                 (const uint8_t *)buf_ptr, len);

    if (written > 0)
        entry->offset += (uint64_t)written;

    return written;
}

int64_t sys_create(uint64_t path_ptr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    /* Check CAP_FS_WRITE (with token fallback) */
    if (!(proc->capabilities & CAP_FS_WRITE) &&
        !cap_token_check(proc->pid, CAP_FS_WRITE, path))
        return -EACCES;

    /* Check write permission on parent directory */
    {
        char parent_path[MAX_PATH], base_name[MAX_PATH];
        vfs_path_split(path, parent_path, base_name);
        int parent_idx = vfs_resolve_path(parent_path);
        if (parent_idx >= 0) {
            vfs_node_t *parent_node = vfs_get_node(parent_idx);
            if (parent_node && check_file_perm(proc, parent_node, O_WRONLY) != 0)
                return -EACCES;
        }
    }

    /* fd limit check */
    if (proc->rlimit_nfds > 0 &&
        (uint32_t)count_open_fds(proc) >= proc->rlimit_nfds)
        return -EMFILE;

    int node_idx = vfs_create(path);
    if (node_idx < 0)
        return -1;

    /* Set ownership and apply umask */
    {
        vfs_node_t *new_node = vfs_get_node(node_idx);
        if (new_node) {
            new_node->uid = proc->euid;
            new_node->gid = proc->egid;
            new_node->mode = 0666 & ~proc->umask;
        }
    }

    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (fd_is_free(&proc->fd_table[fd])) {
            proc->fd_table[fd].node = vfs_get_node(node_idx);
            proc->fd_table[fd].offset = 0;
            proc->fd_table[fd].pipe = NULL;
            proc->fd_table[fd].pipe_write = 0;
            proc->fd_table[fd].pty = NULL;
            proc->fd_table[fd].pty_is_master = 0;
            proc->fd_table[fd].unix_sock = NULL;
            proc->fd_table[fd].eventfd = NULL;
            proc->fd_table[fd].epoll = NULL;
            proc->fd_table[fd].uring = NULL;
            proc->fd_table[fd].open_flags = O_RDWR;  /* create implies read+write */
            proc->fd_table[fd].fd_flags = 0;
            return fd;
        }
    }

    return -1;
}

int64_t sys_unlink(uint64_t path_ptr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    /* Check CAP_FS_WRITE (with token fallback) */
    if (!(proc->capabilities & CAP_FS_WRITE) &&
        !cap_token_check(proc->pid, CAP_FS_WRITE, path))
        return -EACCES;

    /* Check write permission on parent directory + sticky bit */
    {
        char parent_path[MAX_PATH], base_name[MAX_PATH];
        vfs_path_split(path, parent_path, base_name);
        int parent_idx = vfs_resolve_path(parent_path);
        if (parent_idx >= 0) {
            vfs_node_t *parent_node = vfs_get_node(parent_idx);
            if (parent_node) {
                if (check_file_perm(proc, parent_node, O_WRONLY) != 0)
                    return -EACCES;
                /* Sticky bit: only root, file owner, or dir owner can delete */
                if (parent_node->mode & VFS_MODE_STICKY) {
                    int file_idx = vfs_resolve_path(path);
                    if (file_idx >= 0) {
                        vfs_node_t *file_node = vfs_get_node(file_idx);
                        if (file_node && proc->euid != 0 &&
                            proc->euid != file_node->uid &&
                            proc->euid != parent_node->uid)
                            return -EACCES;
                    }
                }
            }
        }
    }

    return vfs_delete(path);
}

int64_t sys_readdir(uint64_t dir_path_ptr, uint64_t index,
                            uint64_t dirent_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    char raw_path[MAX_PATH], dir_path[MAX_PATH];
    if (copy_string_from_user((const char *)dir_path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    if (validate_user_ptr(dirent_ptr, sizeof(vfs_dirent_t)) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, dir_path);

    vfs_dirent_t ent;
    if (vfs_readdir(dir_path, (uint32_t)index, &ent) != 0)
        return -1;

    /* Copy result to user buffer */
    uint8_t *dst = (uint8_t *)dirent_ptr;
    const uint8_t *src = (const uint8_t *)&ent;
    for (uint64_t i = 0; i < sizeof(vfs_dirent_t); i++)
        dst[i] = src[i];

    return 0;
}

int64_t sys_mkdir(uint64_t path_ptr, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    /* Check CAP_FS_WRITE (with token fallback) */
    if (!(proc->capabilities & CAP_FS_WRITE) &&
        !cap_token_check(proc->pid, CAP_FS_WRITE, path))
        return -EACCES;

    /* Check write permission on parent directory */
    {
        char parent_path[MAX_PATH], base_name[MAX_PATH];
        vfs_path_split(path, parent_path, base_name);
        int parent_idx = vfs_resolve_path(parent_path);
        if (parent_idx >= 0) {
            vfs_node_t *parent_node = vfs_get_node(parent_idx);
            if (parent_node && check_file_perm(proc, parent_node, O_WRONLY) != 0)
                return -EACCES;
        }
    }

    int rc = vfs_mkdir(path);
    if (rc >= 0) {
        /* Set ownership and apply umask */
        vfs_node_t *new_node = vfs_get_node(rc);
        if (new_node) {
            new_node->uid = proc->euid;
            new_node->gid = proc->egid;
            new_node->mode = 0777 & ~proc->umask;
        }
    }
    return (rc >= 0) ? 0 : -1;
}

int64_t sys_seek(uint64_t fd, uint64_t offset_arg, uint64_t whence,
                          uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    if (fd >= MAX_FDS)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    fd_entry_t *entry = &proc->fd_table[fd];
    if (entry->node == NULL)
        return -1;

    vfs_node_t *node = entry->node;
    int64_t new_offset;

    switch (whence) {
    case SEEK_SET:
        new_offset = (int64_t)offset_arg;
        break;
    case SEEK_CUR:
        new_offset = (int64_t)entry->offset + (int64_t)offset_arg;
        break;
    case SEEK_END:
        new_offset = (int64_t)node->size + (int64_t)offset_arg;
        break;
    default:
        return -1;
    }

    if (new_offset < 0 || (uint64_t)new_offset > node->size)
        return -1;

    entry->offset = (uint64_t)new_offset;
    return new_offset;
}

int64_t sys_truncate(uint64_t path_ptr, uint64_t new_size,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    /* Check CAP_FS_WRITE (with token fallback) */
    if (!(proc->capabilities & CAP_FS_WRITE) &&
        !cap_token_check(proc->pid, CAP_FS_WRITE, path))
        return -EACCES;

    int node_idx = vfs_resolve_path(path);
    if (node_idx < 0)
        return -ENOENT;

    vfs_node_t *node = vfs_get_node(node_idx);
    if (!node)
        return -ENOENT;
    if (check_node_access(proc, node, VFS_PERM_WRITE) != 0)
        return -EACCES;

    return vfs_truncate_node(node_idx, new_size);
}

int64_t sys_chdir(uint64_t path_ptr, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    int idx = vfs_resolve_path(path);
    if (idx < 0)
        return -1;

    vfs_node_t *node = vfs_get_node(idx);
    if (!node || node->type != VFS_DIRECTORY)
        return -1;

    /* Build canonical path by walking VFS node chain to root */
    if (idx == 0) {
        proc->cwd[0] = '/';
        proc->cwd[1] = '\0';
    } else {
        int chain[64];
        int depth = 0;
        for (int n = idx; n > 0 && depth < 64; n = vfs_get_node(n)->parent)
            chain[depth++] = n;

        int pos = 0;
        for (int d = depth - 1; d >= 0 && pos < MAX_PATH - 2; d--) {
            proc->cwd[pos++] = '/';
            const char *nm = vfs_get_node(chain[d])->name;
            for (int j = 0; nm[j] && pos < MAX_PATH - 1; j++)
                proc->cwd[pos++] = nm[j];
        }
        if (pos == 0) proc->cwd[pos++] = '/';
        proc->cwd[pos] = '\0';
    }

    return 0;
}

int64_t sys_getcwd(uint64_t buf_ptr, uint64_t size,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    if (size == 0)
        return -1;
    if (validate_user_ptr(buf_ptr, size) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    char *dst = (char *)buf_ptr;
    const char *src = proc->cwd;
    uint64_t i = 0;
    while (i < size - 1 && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return (int64_t)i;
}

int64_t sys_fstat(uint64_t fd, uint64_t stat_ptr,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    if (fd >= MAX_FDS)
        return -EBADF;
    if (validate_user_ptr(stat_ptr, sizeof(struct linux_stat)) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    fd_entry_t *entry = &proc->fd_table[fd];
    if (entry->node == NULL)
        return -EBADF;

    vfs_node_t *node = entry->node;
    int node_idx = vfs_node_index(node);

    struct linux_stat ls;
    fill_linux_stat(&ls, node, node_idx >= 0 ? node_idx : 0);

    uint8_t *dst = (uint8_t *)stat_ptr;
    const uint8_t *src = (const uint8_t *)&ls;
    for (uint64_t i = 0; i < sizeof(struct linux_stat); i++)
        dst[i] = src[i];

    return 0;
}

int64_t sys_rename(uint64_t old_path_ptr, uint64_t new_path_ptr,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char raw_old[MAX_PATH], raw_new[MAX_PATH];
    char old_path[MAX_PATH], new_path[MAX_PATH];
    if (copy_string_from_user((const char *)old_path_ptr, raw_old, MAX_PATH) != 0)
        return -1;
    if (copy_string_from_user((const char *)new_path_ptr, raw_new, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_old, old_path);
    resolve_user_path(proc, raw_new, new_path);

    /* Check CAP_FS_WRITE (with token fallback) */
    if (!(proc->capabilities & CAP_FS_WRITE) &&
        !cap_token_check(proc->pid, CAP_FS_WRITE, old_path))
        return -EACCES;

    /* Renaming needs write access to both directories involved */
    int perm = check_parent_write(proc, old_path);
    if (perm != 0)
        return perm;
    perm = check_parent_write(proc, new_path);
    if (perm != 0)
        return perm;

    return vfs_rename(old_path, new_path);
}

/* renameat2(olddirfd, oldpath, newdirfd, newpath, flags) — wrapper */
int64_t sys_renameat2(uint64_t olddirfd, uint64_t old_path_ptr,
                      uint64_t newdirfd, uint64_t new_path_ptr, uint64_t flags) {
    (void)olddirfd; (void)newdirfd; (void)flags;
    /* Ignore dirfd (only AT_FDCWD supported) and flags */
    return sys_rename(old_path_ptr, new_path_ptr, 0, 0, 0);
}

int64_t sys_chmod(uint64_t path_ptr, uint64_t mode,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;
    resolve_user_path(proc, raw_path, path);

    /* Permission check: only root or file owner can chmod */
    if (proc->euid != 0) {
        int idx = vfs_resolve_path(path);
        if (idx < 0) return -1;
        vfs_node_t *node = vfs_get_node(idx);
        if (node && node->uid != proc->euid)
            return -EPERM;
    }

    return vfs_chmod(path, (uint16_t)mode);
}

int64_t sys_symlink(uint64_t target_ptr, uint64_t path_ptr,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char target[MAX_PATH], raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)target_ptr, target, MAX_PATH) != 0)
        return -EFAULT;
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    if (!(proc->capabilities & CAP_FS_WRITE) &&
        !cap_token_check(proc->pid, CAP_FS_WRITE, raw_path))
        return -EACCES;

    resolve_user_path(proc, raw_path, path);
    int ret = vfs_symlink(path, target);
    return ret < 0 ? ret : 0;  /* POSIX: return 0 on success */
}

int64_t sys_readlink(uint64_t path_ptr, uint64_t buf_ptr,
                             uint64_t bufsize, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;
    if (bufsize == 0 || bufsize > MAX_PATH)
        return -EINVAL;
    if (validate_user_ptr(buf_ptr, bufsize) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    resolve_user_path(proc, raw_path, path);

    /* Read into kernel buffer first, then copy to user */
    char kbuf[MAX_PATH];
    int ret = vfs_readlink(path, kbuf, bufsize);
    if (ret < 0) return ret;

    /* Copy to user via HHDM */
    uint64_t *pte = vmm_get_pte(proc->cr3, buf_ptr);
    if (!pte || !(*pte & PTE_PRESENT)) return -EFAULT;
    uint64_t phys = (*pte & PTE_ADDR_MASK) + (buf_ptr & 0xFFF);
    char *ubuf = (char *)PHYS_TO_VIRT(phys);
    for (int i = 0; i < ret + 1; i++)  /* +1 for null terminator */
        ubuf[i] = kbuf[i];

    return ret;
}

int64_t sys_fsstat(uint64_t buf_ptr, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (validate_user_ptr(buf_ptr, 24) != 0) return -1;

    uint32_t *out = (uint32_t *)buf_ptr;
    if (limnfs_mounted()) {
        extern int limnfs_get_stats(uint32_t *total, uint32_t *free_blk,
                                     uint32_t *total_ino, uint32_t *free_ino);
        uint32_t tb, fb, ti, fi;
        limnfs_get_stats(&tb, &fb, &ti, &fi);
        out[0] = tb;
        out[1] = fb;
        out[2] = ti;
        out[3] = fi;
        out[4] = 4096;  /* LIMNFS_BLOCK_SIZE */
        out[5] = 1;     /* mounted */
    } else {
        for (int i = 0; i < 6; i++) out[i] = 0;
    }
    return 0;
}

int64_t sys_mount(uint64_t path_ptr, uint64_t type_ptr,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH], fstype[32];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;
    if (copy_string_from_user((const char *)type_ptr, fstype, 32) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    /* Only root can mount */
    if (proc->euid != 0)
        return -EPERM;

    resolve_user_path(proc, raw_path, path);
    return vfs_mount(path, fstype);
}

int64_t sys_umount(uint64_t path_ptr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    if (proc->euid != 0)
        return -EPERM;

    resolve_user_path(proc, raw_path, path);
    return vfs_umount(path);
}

int64_t sys_mkfifo(uint64_t path_ptr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    char raw_path[MAX_PATH], path[MAX_PATH];
    if (copy_string_from_user((const char *)path_ptr, raw_path, MAX_PATH) != 0)
        return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    if (!(proc->capabilities & CAP_FS_WRITE))
        return -EACCES;

    resolve_user_path(proc, raw_path, path);
    int ret = vfs_mkfifo(path);
    return ret < 0 ? ret : 0;
}

/* Linux getdents64: read directory entries from an fd */
int64_t sys_getdents64(uint64_t fd, uint64_t buf_ptr, uint64_t bufsize,
                                uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    if (fd >= MAX_FDS) return -EBADF;
    if (bufsize == 0) return -EINVAL;
    if (validate_user_ptr(buf_ptr, bufsize) != 0) return -EFAULT;

    thread_t *t = thread_get_current();
    process_t *proc = t ? t->process : NULL;
    if (!proc) return -1;

    fd_entry_t *fde = &proc->fd_table[fd];
    if (!fde->node) return -EBADF;
    if (fde->node->type != VFS_DIRECTORY) return -ENOTDIR;

    int dir_idx = vfs_node_index(fde->node);
    if (dir_idx < 0) return -EBADF;

    /*
     * Linux struct linux_dirent64:
     *   uint64_t d_ino;      (8)
     *   int64_t  d_off;      (8)
     *   uint16_t d_reclen;   (2)
     *   uint8_t  d_type;     (1)
     *   char     d_name[];   (variable, NUL-terminated)
     *   // d_reclen = 8+8+2+1+strlen(name)+1, aligned to 8 bytes
     */

    uint8_t *buf = (uint8_t *)buf_ptr;
    uint64_t pos = 0;
    uint32_t index = (uint32_t)fde->offset;  /* use fd offset as directory index */

    int nc = vfs_get_node_count();
    uint32_t live = 0;
    for (int i = 0; i < nc; i++) {
        vfs_node_t *child = vfs_get_node(i);
        if (!child || child->parent != dir_idx) continue;
        if (live < index) { live++; continue; }

        /* Calculate entry size */
        int namelen = 0;
        while (child->name[namelen]) namelen++;
        uint16_t reclen = (uint16_t)((19 + namelen + 8) & ~7ULL);  /* align to 8 */

        if (pos + reclen > bufsize) break;  /* buffer full */

        /* Fill linux_dirent64 */
        uint64_t ino = (uint64_t)(i + 1);
        uint8_t dtype = 0;
        switch (child->type) {
            case VFS_FILE:      dtype = 8; break;  /* DT_REG */
            case VFS_DIRECTORY: dtype = 4; break;  /* DT_DIR */
            case VFS_SYMLINK:   dtype = 10; break; /* DT_LNK */
            case VFS_FIFO:      dtype = 1; break;  /* DT_FIFO */
        }

        /* d_ino (8 bytes) */
        for (int b = 0; b < 8; b++) buf[pos + b] = (ino >> (b * 8)) & 0xFF;
        /* d_off (8 bytes) — next offset */
        uint64_t next_off = live + 1;
        for (int b = 0; b < 8; b++) buf[pos + 8 + b] = (next_off >> (b * 8)) & 0xFF;
        /* d_reclen (2 bytes) */
        buf[pos + 16] = reclen & 0xFF;
        buf[pos + 17] = (reclen >> 8) & 0xFF;
        /* d_type (1 byte) */
        buf[pos + 18] = dtype;
        /* d_name (NUL-terminated) */
        for (int j = 0; j < namelen; j++) buf[pos + 19 + j] = (uint8_t)child->name[j];
        buf[pos + 19 + namelen] = '\0';
        /* Zero padding to reclen */
        for (uint16_t p = 19 + namelen + 1; p < reclen; p++) buf[pos + p] = 0;

        pos += reclen;
        live++;
        fde->offset = live;  /* update fd offset for next call */
    }

    return (int64_t)pos;  /* bytes written, 0 = end of directory */
}
