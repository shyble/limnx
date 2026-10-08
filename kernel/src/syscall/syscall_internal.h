#ifndef LIMNX_SYSCALL_INTERNAL_H
#define LIMNX_SYSCALL_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "syscall/syscall.h"
#include "proc/process.h"
#include "fs/vfs.h"
#include "arch/paging.h"

/* ---- Pipe and shared memory (extracted to ipc/) ---- */
#include "ipc/pipe.h"
#include "ipc/shm.h"

/* ---- Syscall handler function type ---- */

typedef int64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* ---- fcntl constants ---- */

#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4

/* ---- arch_prctl constants ---- */

#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003

/* ---- TLB flush (via HAL) ---- */

static inline void invlpg_addr(uint64_t addr) {
    arch_flush_tlb_page(addr);
}

/* ---- Shared helper prototypes (defined in syscall.c) ---- */

int validate_user_ptr(uint64_t ptr, uint64_t len);
int copy_string_from_user(const char *user_src, char *kern_dst, uint64_t max_len);
void resolve_user_path(process_t *proc, const char *path, char *out);
int fd_is_free(const fd_entry_t *e);
void fd_close(fd_entry_t *entry);
int check_file_perm(const process_t *proc, const vfs_node_t *node, uint8_t access);
int check_node_access(const process_t *proc, const vfs_node_t *node, int mask);
int check_node_access_real(const process_t *proc, const vfs_node_t *node, int mask);
int check_parent_write(const process_t *proc, const char *path);
int count_open_fds(process_t *proc);
int16_t poll_check_fd(process_t *proc, int fd, int16_t events);

/* ---- Syscall handler prototypes ---- */

/* FS */
int64_t sys_open(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_read(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_close(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_stat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fwrite(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unlink(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_readdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mkdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_seek(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_truncate(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_chdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getcwd(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fstat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_rename(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_renameat2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getrandom(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fork_plain(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_chmod(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fsstat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_symlink(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_readlink(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Proc */
void process_terminate(thread_t *t, int64_t status);
int64_t sys_exit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_exec(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_execve(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fork(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_waitpid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getpid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_kill(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setpgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getpgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_procinfo(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* MM */
int64_t sys_mmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_munmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fmmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mmap2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mmap_file(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mprotect(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mmap_guard(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_shmget(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_shmat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_shmdt(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* FD */
int64_t sys_dup(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_dup2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fcntl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pipe(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pipe2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ioctl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_openpty(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Net */
int64_t sys_socket(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_bind(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sendto(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_recvfrom(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_socket(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_connect(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_listen(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_accept(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_send(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_recv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_close(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_setopt(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcp_to_fd(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Signal */
int64_t sys_sigaction(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigreturn(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigprocmask(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* IPC */
int64_t sys_unix_socket(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unix_bind(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unix_listen(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unix_accept(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unix_connect(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_agent_register(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_agent_lookup(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_agent_send(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_agent_recv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_eventfd(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_ctl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_futex_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_futex_wake(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_topic_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_topic_subscribe(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_topic_publish(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_topic_recv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Security */
int64_t sys_getuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getcap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setcap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getrlimit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setrlimit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_seccomp(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setaudit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_token_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_token_revoke(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_token_list(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_token_delegate(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ns_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ns_join(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ns_setquota(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_chown(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchown(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_umask(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_geteuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getegid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getgroups(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setgroups(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Infer */
int64_t sys_infer_register(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_request(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_health(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_route(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_set_policy(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_queue_stat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_cache_ctrl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_submit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_poll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_result(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_infer_swap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Misc */
int64_t sys_write(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_yield(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getchar(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_gettime(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_nanosleep(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getenv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setenv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_poll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ppoll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_select(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_arch_prctl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_swap_stat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_environ(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_uring_setup(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_uring_enter(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_task_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_task_depend(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_task_start(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_task_complete(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_task_status(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_task_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_super_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_super_add(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_super_set_policy(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_super_start(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_super_list(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_super_stop(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int64_t sys_mkfifo(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mount(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_umount(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setsid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getdents64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fstatat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_openat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mkdirat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unlinkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_symlinkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_readlinkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchmodat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchownat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_faccessat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_brk(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_set_tid_address(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_exit_group(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getppid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_writev(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_set_robust_list(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_rseq(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getsid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcsetpgrp(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tcgetpgrp(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int64_t sys_uname(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_gettid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tgkill(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_getres(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_dup3(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_readv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ftruncate(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_utimensat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Accelerator */
int64_t sys_accel_submit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_accel_poll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_accel_info(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#endif /* LIMNX_SYSCALL_INTERNAL_H */
