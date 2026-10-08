/*
 * Limnx libc — portable C syscall wrappers
 *
 * Replaces the NASM syscalls.asm with arch-independent C using
 * inline assembly from arch/<ARCH>/syscall_arch.h.
 */

#if defined(__x86_64__)
#include "arch/x86_64/syscall_arch.h"
#elif defined(__aarch64__)
#include "arch/arm64/syscall_arch.h"
#endif

/* Syscall numbers — single source of truth */
#include "limnx/syscall_nr.h"

/* AT_FDCWD: dirfd sentinel meaning "resolve relative to cwd" */
#define AT_FDCWD (-100)

/* --- Syscall wrappers --- */

long sys_write(const void *buf, unsigned long len) {
    return __syscall3(SYS_WRITE, 1, (long)buf, (long)len);  /* fd=1 (stdout) */
}

long sys_yield(void) {
    return __syscall0(SYS_SCHED_YIELD);
}

void __attribute__((noreturn)) sys_exit(long status) {
    __syscall1(SYS_EXIT, status);
    __builtin_unreachable();
}

long sys_open(const char *path, unsigned long flags) {
#ifdef __aarch64__
    return __syscall3(SYS_OPEN, AT_FDCWD, (long)path, (long)flags);
#else
    return __syscall2(SYS_OPEN, (long)path, (long)flags);
#endif
}

long sys_read(long fd, void *buf, unsigned long len) {
    return __syscall3(SYS_READ, fd, (long)buf, (long)len);
}

long sys_close(long fd) {
    return __syscall1(SYS_CLOSE, fd);
}

long sys_stat(const char *path, void *stat_buf) {
#ifdef __aarch64__
    return __syscall4(SYS_STAT, AT_FDCWD, (long)path, (long)stat_buf, 0);
#else
    return __syscall2(SYS_STAT, (long)path, (long)stat_buf);
#endif
}

long sys_exec(const char *path, const char **argv) {
    return __syscall2(SYS_EXEC_OLD, (long)path, (long)argv);
}

long sys_socket(void) {
    return __syscall0(SYS_SOCKET);
}

long sys_bind(long sockfd, unsigned long port) {
    return __syscall2(SYS_BIND, sockfd, (long)port);
}

long sys_sendto(long sockfd, const void *buf, unsigned long len,
                unsigned long dst_ip, unsigned long dst_port) {
    return __syscall5(SYS_SENDTO, sockfd, (long)buf, (long)len, (long)dst_ip, (long)dst_port);
}

long sys_recvfrom(long sockfd, void *buf, unsigned long len,
                  void *src_ip_ptr, void *src_port_ptr) {
    return __syscall5(SYS_RECVFROM, sockfd, (long)buf, (long)len, (long)src_ip_ptr, (long)src_port_ptr);
}

long sys_fwrite(long fd, const void *buf, unsigned long len) {
    return __syscall3(SYS_WRITE, fd, (long)buf, (long)len);
}

long sys_create(const char *path) {
#ifdef __aarch64__
    /* creat → openat(AT_FDCWD, path, O_CREAT|O_WRONLY|O_TRUNC, 0666) */
    return __syscall4(SYS_CREAT, AT_FDCWD, (long)path, 0x241, 0666);
#else
    return __syscall1(SYS_CREAT, (long)path);
#endif
}

long sys_unlink(const char *path) {
#ifdef __aarch64__
    return __syscall3(SYS_UNLINK, AT_FDCWD, (long)path, 0);
#else
    return __syscall1(SYS_UNLINK, (long)path);
#endif
}

long sys_mmap(unsigned long num_pages) {
    /* Linux mmap(addr=0, len=bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, fd=-1, off=0) */
    return __syscall6(SYS_MMAP, 0, (long)(num_pages * 4096), 3, 0x22, -1, 0);
}

long sys_munmap(unsigned long virt_addr) {
    return __syscall1(SYS_MUNMAP, (long)virt_addr);
}

long sys_getchar(void) {
    return __syscall0(SYS_GETCHAR);
}

long sys_waitpid(long pid) {
    int status = 0;
    long ret = __syscall4(SYS_WAIT4, pid, (long)&status, 0, 0);
    if (ret > 0) return (status >> 8) & 0xFF;  /* extract exit code */
    return ret;
}

long sys_waitpid_flags(long pid, long flags) {
    int status = 0;
    long ret = __syscall4(SYS_WAIT4, pid, (long)&status, flags, 0);
    if (ret > 0 && (flags & 1) == 0) return (status >> 8) & 0xFF;
    return ret;  /* WNOHANG: return pid or 0 */
}

long sys_pipe(long *rfd_ptr, long *wfd_ptr) {
    int pipefd[2];
    long ret = __syscall2(SYS_PIPE, (long)pipefd, 0);
    if (ret == 0) {
        *rfd_ptr = pipefd[0];
        *wfd_ptr = pipefd[1];
    }
    return ret;
}

long sys_getpid(void) {
    return __syscall0(SYS_GETPID);
}

long sys_fmmap(long fd) {
    return __syscall1(SYS_FMMAP, fd);
}

long sys_readdir(const char *dir_path, unsigned long index, void *dirent_ptr) {
    return __syscall3(SYS_READDIR, (long)dir_path, (long)index, (long)dirent_ptr);
}

long sys_mkdir(const char *path) {
#ifdef __aarch64__
    return __syscall3(SYS_MKDIR, AT_FDCWD, (long)path, 0755);
#else
    return __syscall1(SYS_MKDIR, (long)path);
#endif
}

long sys_seek(long fd, long offset, int whence) {
    return __syscall3(SYS_LSEEK, fd, offset, (long)whence);
}

long sys_truncate(const char *path, unsigned long new_size) {
    return __syscall2(SYS_TRUNCATE, (long)path, (long)new_size);
}

long sys_chdir(const char *path) {
    return __syscall1(SYS_CHDIR, (long)path);
}

long sys_getcwd(char *buf, unsigned long size) {
    return __syscall2(SYS_GETCWD, (long)buf, (long)size);
}

long sys_fstat(long fd, void *stat_buf) {
    return __syscall2(SYS_FSTAT, fd, (long)stat_buf);
}

long sys_rename(const char *old_path, const char *new_path) {
#ifdef __aarch64__
    /* renameat2(AT_FDCWD, old, AT_FDCWD, new, 0) */
    return __syscall5(SYS_RENAME, AT_FDCWD, (long)old_path, AT_FDCWD, (long)new_path, 0);
#else
    return __syscall2(SYS_RENAME, (long)old_path, (long)new_path);
#endif
}

long sys_dup(long fd) {
#ifdef __aarch64__
    /* dup3(oldfd, newfd, 0) — but dup has no newfd, use fcntl F_DUPFD instead */
    return __syscall3(SYS_FCNTL, fd, 0 /* F_DUPFD */, 0);
#else
    return __syscall1(SYS_DUP, fd);
#endif
}

long sys_dup2(long oldfd, long newfd) {
#ifdef __aarch64__
    return __syscall3(SYS_DUP2, oldfd, newfd, 0);
#else
    return __syscall2(SYS_DUP2, oldfd, newfd);
#endif
}

long sys_kill(long pid, long signal) {
    return __syscall2(SYS_KILL, pid, signal);
}

long sys_fcntl(long fd, long cmd, long arg) {
    return __syscall3(SYS_FCNTL, fd, cmd, arg);
}

long sys_setpgid(long pid, long pgid) {
    return __syscall2(SYS_SETPGID, pid, pgid);
}

long sys_getpgid(long pid) {
    return __syscall1(SYS_GETPGID, pid);
}

long sys_chmod(const char *path, long mode) {
#ifdef __aarch64__
    return __syscall3(SYS_CHMOD, AT_FDCWD, (long)path, mode);
#else
    return __syscall2(SYS_CHMOD, (long)path, mode);
#endif
}

long sys_shmget(long key, long num_pages) {
    return __syscall2(SYS_SHMGET, key, num_pages);
}

long sys_shmat(long shmid) {
    return __syscall1(SYS_SHMAT, shmid);
}

long sys_shmdt(long addr) {
    return __syscall1(SYS_SHMDT, addr);
}

long sys_fork(void) {
    return __syscall0(SYS_FORK);
}

long sys_sigaction(int signum, void (*handler)(int)) {
    return __syscall2(SYS_RT_SIGACTION, (long)signum, (long)handler);
}

long sys_sigaction3(int signum, void (*handler)(int), int flags) {
    return __syscall3(SYS_RT_SIGACTION, (long)signum, (long)handler, (long)flags);
}

void sys_sigreturn(void) {
    __syscall0(SYS_RT_SIGRETURN);
}

long sys_sigprocmask(int how, unsigned int new_mask, unsigned int *old_mask) {
    return __syscall3(SYS_RT_SIGPROCMASK, (long)how, (long)new_mask, (long)old_mask);
}

long sys_openpty(long *master_fd, long *slave_fd) {
    return __syscall2(SYS_OPENPTY, (long)master_fd, (long)slave_fd);
}

long sys_tcp_socket(void) {
    return __syscall0(SYS_TCP_SOCKET);
}

long sys_tcp_connect(long conn, unsigned int ip, int port) {
    return __syscall3(SYS_TCP_CONNECT, conn, (long)ip, (long)port);
}

long sys_tcp_listen(long conn, int port) {
    return __syscall2(SYS_TCP_LISTEN, conn, (long)port);
}

long sys_tcp_accept(long listen_conn) {
    return __syscall1(SYS_TCP_ACCEPT, listen_conn);
}

long sys_tcp_send(long conn, const void *buf, long len) {
    return __syscall3(SYS_TCP_SEND, conn, (long)buf, len);
}

long sys_tcp_recv(long conn, void *buf, long len) {
    return __syscall3(SYS_TCP_RECV, conn, (long)buf, len);
}

long sys_tcp_close(long conn) {
    return __syscall1(SYS_TCP_CLOSE, conn);
}

long sys_tcp_setopt(long conn, long opt, long value) {
    return __syscall3(SYS_TCP_SETOPT, conn, opt, value);
}

long sys_tcp_to_fd(long conn) {
    return __syscall1(SYS_TCP_TO_FD, conn);
}

long sys_ioctl(long fd, long cmd, long arg) {
    return __syscall3(SYS_IOCTL, fd, cmd, arg);
}

long sys_clock_gettime(long clockid, void *timespec_ptr) {
    return __syscall2(SYS_CLOCK_GETTIME, clockid, (long)timespec_ptr);
}

long sys_nanosleep(const void *timespec_ptr) {
    return __syscall1(SYS_NANOSLEEP, (long)timespec_ptr);
}

long sys_getenv(const char *key, char *val_buf, long val_buf_size) {
    return __syscall3(SYS_GETENV, (long)key, (long)val_buf, val_buf_size);
}

long sys_setenv(const char *key, const char *value) {
    return __syscall2(SYS_SETENV, (long)key, (long)value);
}

long sys_poll(void *fds, long nfds, long timeout_ms) {
    return __syscall3(SYS_POLL, (long)fds, nfds, timeout_ms);
}

long sys_getuid(void) {
    return __syscall0(SYS_GETUID);
}

long sys_setuid(long uid) {
    return __syscall1(SYS_SETUID, uid);
}

long sys_getgid(void) {
    return __syscall0(SYS_GETGID);
}

long sys_setgid(long gid) {
    return __syscall1(SYS_SETGID, gid);
}

long sys_getcap(void) {
    return __syscall0(SYS_GETCAP);
}

long sys_setcap(long pid, long caps) {
    return __syscall2(SYS_SETCAP, pid, caps);
}

long sys_getrlimit(long resource, void *rlimit_ptr) {
    return __syscall2(SYS_GETRLIMIT, resource, (long)rlimit_ptr);
}

long sys_setrlimit(long resource, const void *rlimit_ptr) {
    return __syscall2(SYS_SETRLIMIT, resource, (long)rlimit_ptr);
}

long sys_seccomp(unsigned long mask, long strict, unsigned long mask_hi) {
    return __syscall3(SYS_SECCOMP, (long)mask, strict, (long)mask_hi);
}

long sys_seccomp_filter(const unsigned long *bits, long strict) {
    return __syscall4(SYS_SECCOMP, 0, strict, 0, (long)bits);
}

long sys_setaudit(long pid, long flags) {
    return __syscall2(SYS_SETAUDIT, pid, flags);
}

long sys_unix_socket(void) {
    return __syscall0(SYS_UNIX_SOCKET);
}

long sys_unix_bind(long fd, const char *path) {
    return __syscall2(SYS_UNIX_BIND, fd, (long)path);
}

long sys_unix_listen(long fd) {
    return __syscall1(SYS_UNIX_LISTEN, fd);
}

long sys_unix_accept(long fd) {
    return __syscall1(SYS_UNIX_ACCEPT, fd);
}

long sys_unix_connect(const char *path) {
    return __syscall1(SYS_UNIX_CONNECT, (long)path);
}

long sys_agent_register(const char *name) {
    return __syscall1(SYS_AGENT_REGISTER, (long)name);
}

long sys_agent_lookup(const char *name, long *pid_out) {
    return __syscall2(SYS_AGENT_LOOKUP, (long)name, (long)pid_out);
}

long sys_eventfd(long flags) {
    return __syscall1(SYS_EVENTFD2, flags);
}

long sys_epoll_create(long flags) {
    return __syscall1(SYS_EPOLL_CREATE1, flags);
}

long sys_epoll_ctl(long epfd, long op, long fd, void *event) {
    return __syscall4(SYS_EPOLL_CTL, epfd, op, fd, (long)event);
}

long sys_epoll_wait(long epfd, void *events, long max_events, long timeout_ms) {
    return __syscall4(SYS_EPOLL_WAIT, epfd, (long)events, max_events, timeout_ms);
}

long sys_swap_stat(void *stat) {
    return __syscall1(SYS_SWAP_STAT, (long)stat);
}

long sys_infer_register(const char *name, const char *sock_path) {
    return __syscall2(SYS_INFER_REGISTER, (long)name, (long)sock_path);
}

long sys_infer_request(const char *name, const void *req_buf, long req_len,
                       void *resp_buf, long resp_len) {
    return __syscall5(SYS_INFER_REQUEST, (long)name, (long)req_buf, req_len, (long)resp_buf, resp_len);
}

long sys_infer_health(long load) {
    return __syscall1(SYS_INFER_HEALTH, load);
}

long sys_infer_route(const char *name) {
    return __syscall1(SYS_INFER_ROUTE, (long)name);
}

long sys_infer_set_policy(long policy) {
    return __syscall1(SYS_INFER_SET_POLICY, policy);
}

long sys_infer_queue_stat(void *stat_ptr) {
    return __syscall1(SYS_INFER_QUEUE_STAT, (long)stat_ptr);
}

long sys_infer_cache_ctrl(long cmd, void *arg) {
    return __syscall2(SYS_INFER_CACHE_CTRL, cmd, (long)arg);
}

long sys_infer_submit(const char *name, const void *req_buf, long req_len, long eventfd_idx) {
    return __syscall4(SYS_INFER_SUBMIT, (long)name, (long)req_buf, req_len, eventfd_idx);
}

long sys_infer_poll(long request_id) {
    return __syscall1(SYS_INFER_POLL, request_id);
}

long sys_infer_result(long request_id, void *resp_buf, long resp_len) {
    return __syscall3(SYS_INFER_RESULT, request_id, (long)resp_buf, resp_len);
}

long sys_infer_swap(const char *name, const char *new_sock_path) {
    return __syscall2(SYS_INFER_SWAP, (long)name, (long)new_sock_path);
}

long sys_uring_setup(long entries, void *params) {
    return __syscall2(SYS_IO_URING_SETUP, entries, (long)params);
}

long sys_uring_enter(long uring_fd, void *sqe_ptr, long count, void *cqe_ptr) {
    return __syscall4(SYS_IO_URING_ENTER, uring_fd, (long)sqe_ptr, count, (long)cqe_ptr);
}

long sys_mmap2(long num_pages, long flags) {
    return __syscall2(SYS_MMAP2, num_pages, flags);
}

long sys_token_create(long perms, long target_pid, const char *resource) {
    return __syscall3(SYS_TOKEN_CREATE, perms, target_pid, (long)resource);
}

long sys_token_revoke(long token_id) {
    return __syscall1(SYS_TOKEN_REVOKE, token_id);
}

long sys_token_list(void *buf, long max_count) {
    return __syscall2(SYS_TOKEN_LIST, (long)buf, max_count);
}

long sys_token_delegate(long parent_id, long target_pid, long perms,
                        const char *resource) {
    return __syscall4(SYS_TOKEN_DELEGATE, parent_id, target_pid, perms, (long)resource);
}

long sys_ns_create(const char *name) {
    return __syscall1(SYS_NS_CREATE, (long)name);
}

long sys_ns_join(long ns_id) {
    return __syscall1(SYS_NS_JOIN, ns_id);
}

long sys_ns_setquota(long ns_id, long resource, long limit) {
    return __syscall3(SYS_NS_SETQUOTA, ns_id, resource, limit);
}

long sys_procinfo(long index, void *info) {
    return __syscall2(SYS_PROCINFO, index, (long)info);
}

long sys_fsstat(void *st) {
    return __syscall1(SYS_FSSTAT, (long)st);
}

long sys_task_create(const char *name, long ns_id) {
    return __syscall2(SYS_TASK_CREATE, (long)name, ns_id);
}

long sys_task_depend(long task_id, long dep_id) {
    return __syscall2(SYS_TASK_DEPEND, task_id, dep_id);
}

long sys_task_start(long task_id) {
    return __syscall1(SYS_TASK_START, task_id);
}

long sys_task_complete(long task_id, long result) {
    return __syscall2(SYS_TASK_COMPLETE, task_id, result);
}

long sys_task_status(long task_id, void *out) {
    return __syscall2(SYS_TASK_STATUS, task_id, (long)out);
}

long sys_task_wait(long task_id) {
    return __syscall1(SYS_TASK_WAIT, task_id);
}

long sys_agent_send(const char *name, const void *msg_buf, long msg_len, long token_id) {
    return __syscall4(SYS_AGENT_SEND, (long)name, (long)msg_buf, msg_len, token_id);
}

long sys_agent_recv(void *msg_buf, long msg_len, long *sender_pid_ptr, long *token_id_ptr) {
    return __syscall4(SYS_AGENT_RECV, (long)msg_buf, msg_len, (long)sender_pid_ptr, (long)token_id_ptr);
}

long sys_futex_wait(volatile unsigned int *addr, unsigned int expected) {
    return __syscall2(SYS_FUTEX_WAIT, (long)addr, (long)expected);
}

long sys_futex_wake(volatile unsigned int *addr, unsigned int max_wake) {
    return __syscall2(SYS_FUTEX_WAKE, (long)addr, (long)max_wake);
}

long sys_mmap_file(long fd, long offset, long num_pages) {
    return __syscall3(SYS_MMAP_FILE, fd, offset, num_pages);
}

long sys_mprotect(long virt_addr, long num_pages, long prot) {
    return __syscall3(SYS_MPROTECT, virt_addr, num_pages, prot);
}

long sys_mmap_guard(long num_pages) {
    return __syscall1(SYS_MMAP_GUARD, num_pages);
}

#ifdef __NR_arch_prctl
long sys_arch_prctl(long code, long addr) {
    return __syscall2(SYS_ARCH_PRCTL, code, addr);
}
#endif

long sys_select(long nfds, void *readfds, void *writefds, long timeout_us) {
    return __syscall4(SYS_SELECT, nfds, (long)readfds, (long)writefds, timeout_us);
}

long sys_super_create(const char *name) {
    return __syscall1(SYS_SUPER_CREATE, (long)name);
}

long sys_super_add(long super_id, const char *elf_path, long ns_id, long caps) {
    return __syscall4(SYS_SUPER_ADD, super_id, (long)elf_path, ns_id, caps);
}

long sys_super_set_policy(long super_id, long policy) {
    return __syscall2(SYS_SUPER_SET_POLICY, super_id, policy);
}

long sys_super_start(long super_id) {
    return __syscall1(SYS_SUPER_START, super_id);
}

long sys_super_list(void *buf, long max_count) {
    return __syscall2(SYS_SUPER_LIST, (long)buf, max_count);
}

long sys_super_stop(long super_id) {
    return __syscall1(SYS_SUPER_STOP, super_id);
}

long sys_pipe2(long *rfd_ptr, long *wfd_ptr, long flags) {
    int pipefd[2];
    long ret = __syscall2(SYS_PIPE2, (long)pipefd, flags);
    if (ret == 0) {
        *rfd_ptr = pipefd[0];
        *wfd_ptr = pipefd[1];
    }
    return ret;
}

long sys_execve(const char *path, const char **argv) {
    return __syscall2(SYS_EXECVE, (long)path, (long)argv);
}

long sys_topic_create(const char *name, unsigned long ns_id) {
    return __syscall2(SYS_TOPIC_CREATE, (long)name, (long)ns_id);
}

long sys_topic_subscribe(unsigned long topic_id) {
    return __syscall1(SYS_TOPIC_SUB, (long)topic_id);
}

long sys_topic_publish(unsigned long topic_id, const void *buf, unsigned long len) {
    return __syscall3(SYS_TOPIC_PUB, (long)topic_id, (long)buf, (long)len);
}

long sys_topic_recv(unsigned long topic_id, void *buf, unsigned long max_len, unsigned long *pub_pid_ptr) {
    return __syscall4(SYS_TOPIC_RECV, (long)topic_id, (long)buf, (long)max_len, (long)pub_pid_ptr);
}

long sys_environ(void *buf, unsigned long buf_size) {
    return __syscall2(SYS_ENVIRON, (long)buf, (long)buf_size);
}

long sys_chown(const char *path, long uid, long gid) {
#ifdef __aarch64__
    return __syscall5(SYS_CHOWN, AT_FDCWD, (long)path, uid, gid, 0);
#else
    return __syscall3(SYS_CHOWN, (long)path, uid, gid);
#endif
}

long sys_fchown(long fd, long uid, long gid) {
    return __syscall3(SYS_FCHOWN, fd, uid, gid);
}

long sys_umask(long mask) {
    return __syscall1(SYS_UMASK, mask);
}

long sys_geteuid(void) {
    return __syscall0(SYS_GETEUID);
}

long sys_getegid(void) {
    return __syscall0(SYS_GETEGID);
}

long sys_getgroups(long max_count, void *buf) {
    return __syscall2(SYS_GETGROUPS, (long)buf, max_count);
}

long sys_setgroups(long count, const void *buf) {
    return __syscall2(SYS_SETGROUPS, (long)buf, count);
}

long sys_symlink(const char *target, const char *path) {
#ifdef __aarch64__
    /* symlinkat(target, AT_FDCWD, linkpath) */
    return __syscall3(SYS_SYMLINK, (long)target, AT_FDCWD, (long)path);
#else
    return __syscall2(SYS_SYMLINK, (long)target, (long)path);
#endif
}

long sys_readlink(const char *path, char *buf, unsigned long bufsize) {
#ifdef __aarch64__
    return __syscall4(SYS_READLINK, AT_FDCWD, (long)path, (long)buf, (long)bufsize);
#else
    return __syscall3(SYS_READLINK, (long)path, (long)buf, (long)bufsize);
#endif
}

long sys_setsid(void) {
    return __syscall0(SYS_SETSID);
}

long sys_getsid(long pid) {
    return __syscall1(SYS_GETSID, pid);
}

long sys_tcsetpgrp(long fd, long pgrp) {
    return __syscall2(SYS_TCSETPGRP, fd, pgrp);
}

long sys_tcgetpgrp(long fd) {
    return __syscall1(SYS_TCGETPGRP, fd);
}

long sys_mkfifo(const char *path) {
    return __syscall1(SYS_MKFIFO, (long)path);
}

long sys_mount(const char *path, const char *fstype) {
    return __syscall2(SYS_MOUNT, (long)path, (long)fstype);
}

long sys_umount(const char *path) {
    return __syscall1(SYS_UMOUNT2, (long)path);
}

/* Accelerator */
long sys_accel_submit(void *req) {
    return __syscall1(SYS_ACCEL_SUBMIT, (long)req);
}

long sys_accel_info(void *info) {
    return __syscall1(SYS_ACCEL_INFO, (long)info);
}
