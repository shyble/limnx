#ifndef LIMNX_SYSCALL_H
#define LIMNX_SYSCALL_H

#include <stdint.h>
#include "errno.h"

/* Syscall numbers — single source of truth */
#include "limnx/syscall_nr.h"

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
/* Capabilities an ordinary user keeps: access is then governed by file
 * permissions. Everything else is dropped when root switches to a user. */
#define CAP_BASIC     (CAP_EXEC | CAP_FS_READ | CAP_FS_WRITE)

/* Resource limits */
#define RLIMIT_MEM   0
#define RLIMIT_CPU   1
#define RLIMIT_NFDS  2

typedef struct rlimit {
    uint64_t current;
    uint64_t max;
} rlimit_t;

/* Audit flags */
#define AUDIT_SYSCALL  (1 << 0)
#define AUDIT_SECURITY (1 << 1)
#define AUDIT_EXEC     (1 << 2)
#define AUDIT_FILE     (1 << 3)

/* waitpid flags */
#define WNOHANG  1

/* Clock IDs */
#define CLOCK_MONOTONIC 1

typedef struct timespec {
    int64_t  tv_sec;
    int64_t  tv_nsec;
} timespec_t;

/* Poll */
#define POLLIN   0x001
#define POLLOUT  0x004
#define POLLERR  0x008
#define POLLHUP  0x010

typedef struct pollfd {
    int32_t  fd;
    int16_t  events;
    int16_t  revents;
} pollfd_t;

/* epoll */
#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_MOD  2
#define EPOLL_CTL_DEL  3
#define EPOLLIN   0x001
#define EPOLLOUT  0x004
#define EPOLLERR  0x008
#define EPOLLHUP  0x010

/* io_uring */
#define IORING_OP_NOP       0
#define IORING_OP_READ      1
#define IORING_OP_WRITE     2
#define IORING_OP_POLL_ADD  3

/* mmap */
#define MMAP_DEMAND  1
#define PROT_NONE   0
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4
#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20

/* User-space address limit */
#define USER_ADDR_MAX 0x0000800000000000ULL

void syscall_init(void);
int64_t syscall_dispatch(uint64_t num, uint64_t arg1, uint64_t arg2,
                          uint64_t arg3, uint64_t arg4, uint64_t arg5);
void syscall_set_kernel_stack(uint64_t rsp);

#endif
