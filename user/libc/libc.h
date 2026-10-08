#ifndef LIMNX_LIBC_H
#define LIMNX_LIBC_H

/* --- Basic types --- */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long      uint64_t;
typedef signed char        int8_t;
typedef signed short       int16_t;
typedef signed int         int32_t;
typedef signed long        int64_t;
typedef uint64_t           size_t;
typedef int64_t            ssize_t;

#define NULL ((void *)0)
#define PAGE_SIZE 4096

/* --- Syscall wrappers --- */

long sys_write(const void *buf, unsigned long len);
long sys_yield(void);
void sys_exit(long status) __attribute__((noreturn));
long sys_open(const char *path, unsigned long flags);
long sys_access(const char *path, long mode);  /* mode: 0 or R=4|W=2|X=1 */
long sys_read(long fd, void *buf, unsigned long len);
long sys_close(long fd);
long sys_stat(const char *path, void *stat_buf);
long sys_exec(const char *path, const char **argv);
long sys_execve(const char *path, const char **argv);
long sys_topic_create(const char *name, unsigned long ns_id);
long sys_topic_subscribe(unsigned long topic_id);
long sys_topic_publish(unsigned long topic_id, const void *buf, unsigned long len);
long sys_topic_recv(unsigned long topic_id, void *buf, unsigned long max_len, unsigned long *pub_pid_ptr);
long sys_socket(void);
long sys_bind(long sockfd, unsigned long port);
long sys_sendto(long sockfd, const void *buf, unsigned long len,
                unsigned long dst_ip, unsigned long dst_port);
long sys_recvfrom(long sockfd, void *buf, unsigned long len,
                  void *src_ip_ptr, void *src_port_ptr);
long sys_fwrite(long fd, const void *buf, unsigned long len);
long sys_create(const char *path);
long sys_unlink(const char *path);
long sys_mmap(unsigned long num_pages);
long sys_munmap(unsigned long virt_addr);
long sys_getchar(void);
long sys_waitpid(long pid);
long sys_pipe(long *rfd_ptr, long *wfd_ptr);
long sys_getpid(void);
long sys_fmmap(long fd);
long sys_readdir(const char *dir_path, unsigned long index, void *dirent_ptr);
long sys_mkdir(const char *path);
long sys_seek(long fd, long offset, int whence);
long sys_truncate(const char *path, unsigned long new_size);
long sys_chdir(const char *path);
long sys_getcwd(char *buf, unsigned long size);
long sys_fstat(long fd, void *stat_buf);
long sys_rename(const char *old_path, const char *new_path);
long sys_dup(long fd);
long sys_dup2(long oldfd, long newfd);
long sys_kill(long pid, long signal);
long sys_fcntl(long fd, long cmd, long arg);
long sys_setpgid(long pid, long pgid);
long sys_getpgid(long pid);
long sys_chmod(const char *path, long mode);
long sys_shmget(long key, long num_pages);
long sys_shmat(long shmid);
long sys_shmdt(long addr);
long sys_fork(void);
long sys_sigaction(int signum, void (*handler)(int));
long sys_sigaction3(int signum, void (*handler)(int), int flags);
long sys_sigreturn(void);
long sys_sigprocmask(int how, unsigned int new_mask, unsigned int *old_mask);
long sys_openpty(long *master_fd, long *slave_fd);
long sys_tcp_socket(void);
long sys_tcp_connect(long conn, unsigned int ip, int port);
long sys_tcp_listen(long conn, int port);
long sys_tcp_accept(long listen_conn);
long sys_tcp_send(long conn, const void *buf, long len);
long sys_tcp_recv(long conn, void *buf, long len);
long sys_tcp_close(long conn);
long sys_tcp_setopt(long conn, long opt, long value);
long sys_tcp_to_fd(long conn);
long sys_ioctl(long fd, long cmd, long arg);
long sys_clock_gettime(long clockid, void *timespec_ptr);
long sys_nanosleep(const void *timespec_ptr);
long sys_getenv(const char *key, char *val_buf, long val_buf_size);
long sys_setenv(const char *key, const char *value);
long sys_poll(void *fds, long nfds, long timeout_ms);
long sys_waitpid_flags(long pid, long flags);
long sys_getuid(void);
long sys_setuid(long uid);
long sys_getgid(void);
long sys_setgid(long gid);
long sys_getcap(void);
long sys_setcap(long pid, long caps);
long sys_getrlimit(long resource, void *rlimit_ptr);
long sys_setrlimit(long resource, const void *rlimit_ptr);
long sys_seccomp(unsigned long mask, long strict, unsigned long mask_hi);
/* Full allowlist for standard syscalls 0-511 (bit N = syscall N allowed). */
#define SECCOMP_FILTER_WORDS 8
#define SECCOMP_ALLOW(bits, nr) \
    do { if ((nr) < 64 * SECCOMP_FILTER_WORDS) \
             (bits)[(nr) / 64] |= 1UL << ((nr) % 64); } while (0)
long sys_seccomp_filter(const unsigned long *bits, long strict);
long sys_setaudit(long pid, long flags);
long sys_unix_socket(void);
long sys_unix_bind(long fd, const char *path);
long sys_unix_listen(long fd);
long sys_unix_accept(long fd);
long sys_unix_connect(const char *path);
long sys_agent_register(const char *name);
long sys_agent_lookup(const char *name, long *pid_out);
long sys_eventfd(long flags);
long sys_chown(const char *path, long uid, long gid);
long sys_fchown(long fd, long uid, long gid);
long sys_umask(long mask);
long sys_geteuid(void);
long sys_getegid(void);
long sys_getgroups(long max_count, void *buf);
long sys_setgroups(long count, const void *buf);
long sys_symlink(const char *target, const char *path);
long sys_readlink(const char *path, char *buf, unsigned long bufsize);
long sys_setsid(void);
long sys_getsid(long pid);
long sys_tcsetpgrp(long fd, long pgrp);
long sys_tcgetpgrp(long fd);
long sys_mkfifo(const char *path);
long sys_mount(const char *path, const char *fstype);
long sys_umount(const char *path);

/* Accelerator */
long sys_accel_submit(void *req);
long sys_accel_info(void *info);

/* Accelerator HAL (auto-falls back to CPU if no device) */
#include "limnx/virtio_accel.h"
int  accel_available(void);
int  accel_get_info(accel_info_t *info);
int  accel_matmul(float *out, const float *a, const float *b,
                  uint32_t a_rows, uint32_t a_cols,
                  uint32_t b_rows, uint32_t b_cols);
int  accel_softmax(float *x, uint32_t size);
int  accel_rmsnorm(float *out, const float *x, const float *weight,
                   uint32_t dim, float eps);
int  accel_silu(float *x, uint32_t size);

/* Signal constants */
#define SIGTSTP  21
#define SIGTTIN  22
#define SIGTTOU  23

/* termios structures (matching kernel termios.h) */
typedef struct {
    unsigned int c_iflag;
    unsigned int c_oflag;
    unsigned int c_cflag;
    unsigned int c_lflag;
    unsigned char c_line;
    unsigned char c_cc[32];
    unsigned int c_ispeed;
    unsigned int c_ospeed;
} termios_t;

typedef struct {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
} winsize_t;

/* termios c_lflag bits — must match kernel (Linux values) */
#define TERMIOS_ISIG    0x0001
#define TERMIOS_ICANON  0x0002
#define TERMIOS_ECHO    0x0008

/* ioctl commands */
#define TCGETS     0x5401
#define TCSETS     0x5402
#define TCSETSW    0x5403
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define TIOCSPGRP  0x5410
#define TIOCGPGRP  0x5411

/* Signal numbers */
#define SIGINT   2
#define SIGKILL  9
#define SIGTERM  15
#define SIGSTOP  19
#define SIGCONT  18

/* Signal handler constants */
#define SIG_DFL  ((void (*)(int))0)
#define SIG_IGN  ((void (*)(int))1)

/* sigprocmask operations */
#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

/* sigaction flags */
#define SA_RESTART  (1 << 0)

/* Open flags */
/* Open flags — Linux-compatible values */
#define O_RDONLY    0x000
#define O_WRONLY    0x001
#define O_RDWR      0x002
#define O_CREAT     0x040     /* Linux 0100 octal = 64 = 0x40 */
#define O_EXCL      0x080     /* Linux 0200 octal */
#define O_TRUNC     0x200     /* Linux 01000 octal */
#define O_APPEND    0x400     /* Linux 02000 octal */
#define O_NONBLOCK  0x800     /* Linux 04000 octal */
#define O_CLOEXEC   0x80000   /* Linux 02000000 octal */

/* fcntl commands */
#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4

/* fd flags */
#define FD_CLOEXEC  0x01

/* waitpid flags */
#define WNOHANG  1

/* errno codes */
#define EPERM    1
#define ENOENT   2
#define ESRCH    3
#define EINTR    4
#define EIO      5
#define EBADF    9
#define EAGAIN  11
#define ENOMEM  12
#define EACCES  13
#define EFAULT  14
#define EEXIST  17
#define EINVAL  22
#define EMFILE  24
#define ENOSYS  38
#define EADDRINUSE  98
#define ENOBUFS    105
#define ENOTCONN   107
#define ECONNREFUSED 111
#define EINPROGRESS  115

extern int errno;

const char *strerror(int errnum);
void perror(const char *msg);

/* Helper: if ret < 0, set errno = -ret and return -1; else return ret */
static inline long __set_errno(long ret) {
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return ret;
}

/* Capability bits */
#define CAP_NET_BIND  (1 << 0)
#define CAP_NET_RAW   (1 << 1)
#define CAP_KILL      (1 << 2)
#define CAP_SETUID    (1 << 3)
#define CAP_SYS_ADMIN (1 << 4)
#define CAP_EXEC      (1 << 5)
#define CAP_FS_WRITE  (1 << 6)
#define CAP_FS_READ   (1 << 7)
#define CAP_INFER     (1 << 8)
#define CAP_XNS_TASK  (1 << 9)
#define CAP_XNS_PUBSUB (1 << 10)
#define CAP_XNS_INFER  (1 << 11)
#define CAP_CHOWN      (1 << 12)
#define CAP_ALL       0x1FFF

/* Resource limit IDs */
#define RLIMIT_MEM   0
#define RLIMIT_CPU   1
#define RLIMIT_NFDS  2

/* Resource limit structure */
typedef struct {
    uint64_t current;
    uint64_t max;
} rlimit_t;

/* Audit flags */
#define AUDIT_SYSCALL  (1 << 0)
#define AUDIT_SECURITY (1 << 1)
#define AUDIT_EXEC     (1 << 2)
#define AUDIT_FILE     (1 << 3)

/* Clock IDs */
#define CLOCK_MONOTONIC 1

/* Time structures */
typedef struct {
    int64_t tv_sec;
    int64_t tv_nsec;
} timespec_t;

/* Poll structures */
#define POLLIN   0x001
#define POLLOUT  0x004
#define POLLERR  0x008
#define POLLHUP  0x010

typedef struct {
    int32_t fd;
    int16_t events;
    int16_t revents;
} pollfd_t;

/* Seek whence */
#define SEEK_SET  0
#define SEEK_CUR  1
#define SEEK_END  2

/* --- Directory entry (matches kernel vfs_dirent_t) --- */

typedef struct dirent {
    char     name[256];
    uint8_t  type;
    uint8_t  pad[7];
    uint64_t size;
} dirent_t;

/* --- Heap allocator --- */

void *malloc(size_t size);
void  free(void *ptr);
void *realloc(void *ptr, size_t new_size);
void *calloc(size_t count, size_t size);

/* --- String functions --- */

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);
void *memmove(void *dst, const void *src, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
char *strtok(char *str, const char *delim);
char *strdup(const char *s);

/* --- Number parsing --- */

int   atoi(const char *s);
long  atol(const char *s);
long  strtol(const char *s, char **endptr, int base);
unsigned long strtoul(const char *s, char **endptr, int base);

/* --- Character classification --- */

int isdigit(int c);
int isalpha(int c);
int isalnum(int c);
int isspace(int c);
int isupper(int c);
int islower(int c);
int toupper(int c);
int tolower(int c);

/* --- Stdlib --- */

int  abs(int n);
long labs(long n);
void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size,
              int (*compar)(const void *, const void *));

/* --- Stdio functions --- */

int puts(const char *s);
int printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* --- Buffered file I/O --- */

typedef struct _FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

FILE  *fopen(const char *path, const char *mode);
int    fclose(FILE *fp);
size_t fread(void *buf, size_t size, size_t count, FILE *fp);
size_t fwrite(const void *buf, size_t size, size_t count, FILE *fp);
char  *fgets(char *buf, int size, FILE *fp);
int    fputs(const char *s, FILE *fp);
int    fputc(int c, FILE *fp);
int    fgetc(FILE *fp);
int    fprintf(FILE *fp, const char *fmt, ...);
int    fflush(FILE *fp);
int    feof(FILE *fp);
int    ferror(FILE *fp);
int    fseek(FILE *fp, long offset, int whence);
int    fileno(FILE *fp);
int    snprintf(char *buf, size_t size, const char *fmt, ...);
int    sprintf(char *buf, const char *fmt, ...);
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
int    sscanf(const char *str, const char *fmt, ...);

/* --- Math functions (float, compiled with -msse2) --- */

float fabsf(float x);
float sqrtf(float x);
float expf(float x);
float logf(float x);
float tanhf(float x);
float floorf(float x);
float ceilf(float x);
float fmaxf(float a, float b);
float fminf(float a, float b);
float sinf(float x);
float cosf(float x);
float sigmoidf(float x);

/* Signal numbers for user-space */
#define SIGCHLD 20

/* --- Eventfd flags --- */

#define EFD_NONBLOCK   (1 << 0)
#define EFD_SEMAPHORE  (1 << 1)

/* --- Stage 37: epoll types --- */

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_MOD  2
#define EPOLL_CTL_DEL  3
#define EPOLLIN   0x001
#define EPOLLOUT  0x004
#define EPOLLERR  0x008
#define EPOLLHUP  0x010

typedef struct epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed)) epoll_event_t;

/* --- Stage 37: io_uring types --- */

#define IORING_OP_NOP       0
#define IORING_OP_READ      1
#define IORING_OP_WRITE     2
#define IORING_OP_POLL_ADD  3

typedef struct uring_sqe {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t reserved;
    int32_t  fd;
    uint64_t off;
    uint64_t addr;
    uint32_t len;
    uint32_t user_data;
} __attribute__((packed)) uring_sqe_t;

typedef struct uring_cqe {
    uint32_t user_data;
    int32_t  res;
    uint32_t flags;
    uint32_t reserved;
} __attribute__((packed)) uring_cqe_t;

/* --- Stage 37: mmap2 flags --- */

#define MMAP_DEMAND  1

/* --- Stage 37 syscalls --- */

long sys_epoll_create(long flags);
long sys_epoll_ctl(long epfd, long op, long fd, epoll_event_t *event);
long sys_epoll_wait(long epfd, epoll_event_t *events, long max_events, long timeout_ms);
long sys_swap_stat(uint32_t *stat);
long sys_infer_register(const char *name, const char *sock_path);
long sys_infer_request(const char *name, const void *req_buf, long req_len,
                       void *resp_buf, long resp_len);
long sys_infer_health(long load);
long sys_infer_route(const char *name);
long sys_infer_set_policy(long policy);
long sys_infer_queue_stat(void *stat_ptr);

/* Inference routing policies */
#define INFER_ROUTE_LEAST_LOADED  0
#define INFER_ROUTE_ROUND_ROBIN   1
#define INFER_ROUTE_WEIGHTED      2

/* Inference queue stat */
typedef struct {
    uint32_t capacity;
    uint32_t pending;
    uint32_t total_queued;
    uint32_t total_timeouts;
} infer_queue_stat_t;

/* Inference cache control */
long sys_infer_cache_ctrl(long cmd, void *arg);

#define INFER_CACHE_FLUSH    0
#define INFER_CACHE_STATS    1
#define INFER_CACHE_SET_TTL  2

typedef struct {
    uint32_t hits;
    uint32_t misses;
    uint32_t evictions;
    uint32_t size;
    uint32_t capacity;
    uint32_t ttl;
} infer_cache_stat_t;

/* Async inference */
long sys_infer_submit(const char *name, const void *req_buf, long req_len, long eventfd_idx);
long sys_infer_poll(long request_id);
long sys_infer_result(long request_id, void *resp_buf, long resp_len);
long sys_infer_swap(const char *name, const char *new_sock_path);
long sys_environ(void *buf, unsigned long buf_size);

#define INFER_STATUS_PENDING  1
#define INFER_STATUS_READY    2

long sys_agent_send(const char *name, const void *msg_buf, long msg_len, long token_id);
long sys_agent_recv(void *msg_buf, long msg_len, long *sender_pid_ptr, long *token_id_ptr);
long sys_uring_setup(long entries, void *params);
long sys_uring_enter(long uring_fd, void *sqe_ptr, long count, void *cqe_ptr);
long sys_mmap2(long num_pages, long flags);
long sys_token_create(long perms, long target_pid, const char *resource);
long sys_token_revoke(long token_id);
long sys_token_list(void *buf, long max_count);
long sys_ns_create(const char *name);
long sys_ns_join(long ns_id);
long sys_futex_wait(volatile unsigned int *addr, unsigned int expected);
long sys_futex_wake(volatile unsigned int *addr, unsigned int max_wake);
long sys_mmap_file(long fd, long offset, long num_pages);
long sys_mprotect(long virt_addr, long num_pages, long prot);
long sys_mmap_guard(long num_pages);

/* mprotect protection flags */
#define PROT_NONE   0
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4

/* --- Userspace sleeping mutex (built on futex) --- */

typedef struct {
    volatile unsigned int state;  /* 0=unlocked, 1=locked-no-waiters, 2=locked-with-waiters */
} umutex_t;

#define UMUTEX_INIT { 0 }

static inline void umutex_lock(umutex_t *m) {
    unsigned int c;
    /* Fast path: try to grab uncontested lock */
    c = __sync_val_compare_and_swap(&m->state, 0, 1);
    if (c == 0) return;  /* Got it */

    /* Slow path: mark as contended and sleep */
    if (c != 2)
        c = __sync_lock_test_and_set(&m->state, 2);
    while (c != 0) {
        sys_futex_wait(&m->state, 2);
        c = __sync_lock_test_and_set(&m->state, 2);
    }
}

static inline void umutex_unlock(umutex_t *m) {
    if (__sync_fetch_and_sub(&m->state, 1) != 1) {
        /* There were waiters (state was 2) — reset to 0 and wake one */
        m->state = 0;
        sys_futex_wake(&m->state, 1);
    }
}

static inline int umutex_trylock(umutex_t *m) {
    return __sync_val_compare_and_swap(&m->state, 0, 1) == 0 ? 0 : -1;
}

/* Process info (matches kernel layout: 64 bytes) */
typedef struct proc_info {
    long     pid;
    long     parent_pid;
    int      state;       /* 0=running, 1=stopped */
    unsigned short uid;
    unsigned short gid;
    char     name[32];
    unsigned char daemon;  /* 1 = daemon (managed by supervisor) */
    unsigned char reserved[7];
} proc_info_t;

long sys_procinfo(long index, proc_info_t *info);

/* Filesystem stats (matches kernel layout: 24 bytes) */
typedef struct fs_stat {
    unsigned int total_blocks;
    unsigned int free_blocks;
    unsigned int total_inodes;
    unsigned int free_inodes;
    unsigned int block_size;
    unsigned int mounted;
} fs_stat_t;

long sys_fsstat(fs_stat_t *st);

/* Workflow task graph */
#define TASK_PENDING  0
#define TASK_RUNNING  1
#define TASK_DONE     2
#define TASK_FAILED   3
#define MAX_TASK_DEPS 4
#define TASK_NAME_MAX 32

typedef struct task_status {
    unsigned int id;
    unsigned char status;
    unsigned char dep_count;
    unsigned char pad[2];
    int          result;
    unsigned int deps[MAX_TASK_DEPS];
    char         name[TASK_NAME_MAX];
} task_status_t;

long sys_task_create(const char *name, long ns_id);
long sys_task_depend(long task_id, long dep_id);
long sys_task_start(long task_id);
long sys_task_complete(long task_id, long result);
long sys_task_status(long task_id, task_status_t *out);
long sys_task_wait(long task_id);

/* Token delegation */
long sys_token_delegate(long parent_id, long target_pid, long perms,
                        const char *resource);

/* Namespace quotas */
#define NS_QUOTA_PROCS     0
#define NS_QUOTA_MEM_PAGES 1

long sys_ns_setquota(long ns_id, long resource, long limit);

/* arch_prctl */
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
long sys_arch_prctl(long code, long addr);

/* select */
typedef struct { uint64_t bits; } fd_set_t;
#define FD_ZERO(s)    ((s)->bits = 0)
#define FD_SET(fd, s) ((s)->bits |= (1ULL << (fd)))
#define FD_CLR(fd, s) ((s)->bits &= ~(1ULL << (fd)))
#define FD_ISSET(fd, s) (((s)->bits >> (fd)) & 1)
long sys_select(long nfds, fd_set_t *readfds, fd_set_t *writefds, long timeout_us);

/* Supervisor trees */
#define SUPER_ONE_FOR_ONE 0
#define SUPER_ONE_FOR_ALL 1
long sys_super_create(const char *name);
long sys_super_add(long super_id, const char *elf_path, long ns_id, long caps);
long sys_super_set_policy(long super_id, long policy);
long sys_super_start(long super_id);
long sys_super_list(void *buf, long max_count);
long sys_super_stop(long super_id);

/* Supervisor info structure (matches kernel super_info_t) */
typedef struct super_info {
    unsigned int id;
    unsigned char used;
    unsigned char policy;
    unsigned char child_count;
    char name[32];
    unsigned long owner_pid;
    unsigned long child_pids[8];
    unsigned int restart_count;
} super_info_t;

/* pipe2 flags — O_CLOEXEC defined above with Linux value */
long sys_pipe2(long *rfd_ptr, long *wfd_ptr, long flags);

/* TCP socket options */
#define TCP_OPT_NONBLOCK 1

/* --- Config file (INI) parsing for /etc/limnx.conf and similar --- */
int  config_get(const char *path, const char *section, const char *key,
                char *out, int out_size);
long config_get_int(const char *path, const char *section, const char *key,
                    long default_val);
int  config_iter_section(const char *path, const char *section, int *state,
                         char *key, int key_size, char *value, int value_size);

/* Convenience: include all sub-headers so existing code keeps working */
#include "tensor.h"
#include "transformer.h"
#include "http.h"
#include "wasm.h"

#endif
