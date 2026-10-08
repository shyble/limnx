#define pr_fmt(fmt) "[tcp]  " fmt
#include "klog.h"
#include "net/tcp.h"
#include "net/net.h"
#include "arch/timer.h"
#include "sched/sched.h"
#include "arch/serial.h"
#include "errno.h"
#include "arch/cpu.h"

/* Poll event bits for tcp_poll */
#define POLLIN   0x001
#define POLLOUT  0x004
#define POLLERR  0x008
#define POLLHUP  0x010

static tcp_conn_t tcp_conns[MAX_TCP_CONNS];
static uint16_t tcp_ephemeral_port = 49152;

/* --- Helpers --- */

static void tcp_memcpy(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++)
        d[i] = s[i];
}

static void tcp_memset(void *dst, uint8_t val, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (uint32_t i = 0; i < n; i++)
        d[i] = val;
}

void tcp_init(void) {
    for (int i = 0; i < MAX_TCP_CONNS; i++)
        tcp_conns[i].in_use = 0;
    pr_info("TCP stack initialized\n");
}

static uint32_t tcp_gen_isn(int conn_idx) {
    return (uint32_t)(arch_timer_get_ticks() * 64000 + (uint32_t)conn_idx * 1000);
}

/* --- TCP Checksum --- */

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                              const uint8_t *tcp_seg, uint32_t tcp_len) {
    uint32_t sum = 0;

    /* Pseudo-header: src_ip, dst_ip in network order, zero, proto=6, tcp_len */
    uint32_t src_n = htonl(src_ip);
    uint32_t dst_n = htonl(dst_ip);

    sum += (src_n >> 16) & 0xFFFF;
    sum += src_n & 0xFFFF;
    sum += (dst_n >> 16) & 0xFFFF;
    sum += dst_n & 0xFFFF;
    sum += htons(6);              /* protocol TCP */
    sum += htons((uint16_t)tcp_len);

    /* TCP segment */
    const uint16_t *ptr = (const uint16_t *)tcp_seg;
    uint32_t remaining = tcp_len;
    while (remaining > 1) {
        sum += *ptr++;
        remaining -= 2;
    }
    if (remaining == 1)
        sum += *(const uint8_t *)ptr;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/* --- Dynamic receive window --- */

static uint16_t tcp_calc_rcv_wnd(tcp_conn_t *conn) {
    uint32_t space = TCP_RX_BUF_SIZE - conn->rx_count;
    return (uint16_t)(space > 0xFFFF ? 0xFFFF : space);
}

/* --- Send helpers --- */

static void tcp_send_segment(tcp_conn_t *conn, uint8_t flags,
                              const uint8_t *data, uint32_t data_len) {
    /* Update receive window before sending */
    conn->rcv_wnd = tcp_calc_rcv_wnd(conn);

    uint8_t seg[20 + TCP_MSS];
    tcp_hdr_t *hdr = (tcp_hdr_t *)seg;

    tcp_memset(seg, 0, 20);
    hdr->src_port    = htons(conn->local_port);
    hdr->dst_port    = htons(conn->remote_port);
    hdr->seq_num     = htonl(conn->snd_nxt);
    hdr->ack_num     = htonl(conn->rcv_nxt);
    hdr->data_offset = (5 << 4);   /* 20 bytes, no options */
    hdr->flags       = flags;
    hdr->window      = htons(conn->rcv_wnd);
    hdr->checksum    = 0;
    hdr->urgent_ptr  = 0;

    if (data && data_len > 0)
        tcp_memcpy(seg + 20, data, data_len);

    uint32_t total = 20 + data_len;
    hdr->checksum = tcp_checksum(conn->local_ip, conn->remote_ip, seg, total);

    net_tx_ipv4(conn->remote_ip, IP_PROTO_TCP, seg, total);
}

static void tcp_send_ack(tcp_conn_t *conn) {
    tcp_send_segment(conn, TCP_ACK, 0, 0);
}

static void tcp_send_rst_for(uint32_t src_ip, uint16_t src_port,
                              uint32_t dst_ip, uint16_t dst_port,
                              uint32_t ack_num) {
    uint8_t seg[20];
    tcp_hdr_t *hdr = (tcp_hdr_t *)seg;

    tcp_memset(seg, 0, 20);
    hdr->src_port    = htons(src_port);
    hdr->dst_port    = htons(dst_port);
    hdr->seq_num     = htonl(ack_num);
    hdr->ack_num     = 0;
    hdr->data_offset = (5 << 4);
    hdr->flags       = TCP_RST | TCP_ACK;
    hdr->window      = 0;
    hdr->checksum    = 0;

    hdr->checksum = tcp_checksum(src_ip, dst_ip, seg, 20);
    net_tx_ipv4(dst_ip, IP_PROTO_TCP, seg, 20);
}

/* --- Connection lookup --- */

static int tcp_find_conn(uint16_t local_port, uint32_t remote_ip,
                          uint16_t remote_port) {
    /* Exact 4-tuple match first */
    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (tcp_conns[i].in_use &&
            tcp_conns[i].local_port == local_port &&
            tcp_conns[i].remote_ip == remote_ip &&
            tcp_conns[i].remote_port == remote_port)
            return i;
    }
    return -1;
}

static int tcp_find_listener(uint16_t local_port) {
    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (tcp_conns[i].in_use &&
            tcp_conns[i].state == TCP_LISTEN &&
            tcp_conns[i].local_port == local_port)
            return i;
    }
    return -1;
}

/* --- RX handler --- */

void tcp_rx(uint32_t src_ip, uint32_t dst_ip, const uint8_t *data, uint32_t len) {
    if (len < 20) return;
    /* Summing a segment that carries a valid checksum yields zero. */
    if (tcp_checksum(src_ip, dst_ip, data, len) != 0) return;

    const tcp_hdr_t *hdr = (const tcp_hdr_t *)data;
    uint16_t src_port = ntohs(hdr->src_port);
    uint16_t dst_port = ntohs(hdr->dst_port);
    uint32_t seq      = ntohl(hdr->seq_num);
    uint32_t ack      = ntohl(hdr->ack_num);
    uint8_t  flags    = hdr->flags;
    uint8_t  hdr_len  = (hdr->data_offset >> 4) * 4;

    if (hdr_len < 20 || hdr_len > len) return;

    const uint8_t *payload = data + hdr_len;
    uint32_t payload_len = len - hdr_len;

    /* Find matching connection */
    int idx = tcp_find_conn(dst_port, src_ip, src_port);

    if (idx < 0) {
        /* Check for listener */
        idx = tcp_find_listener(dst_port);
        if (idx < 0) {
            /* No connection — send RST */
            if (!(flags & TCP_RST)) {
                uint32_t our_ip = 0x0A00020FU; /* 10.0.2.15 */
                tcp_send_rst_for(our_ip, dst_port, src_ip, src_port,
                                  (flags & TCP_ACK) ? ack : seq + 1);
            }
            return;
        }
    }

    tcp_conn_t *conn = &tcp_conns[idx];

    switch (conn->state) {
    case TCP_LISTEN:
        if (flags & TCP_SYN) {
            /* Add to backlog */
            for (int i = 0; i < TCP_BACKLOG_SIZE; i++) {
                if (!conn->backlog[i].valid) {
                    conn->backlog[i].remote_ip = src_ip;
                    conn->backlog[i].remote_port = src_port;
                    conn->backlog[i].remote_seq = seq;
                    conn->backlog[i].valid = 1;
                    return;
                }
            }
            /* Backlog full — ignore */
        }
        return;

    case TCP_SYN_SENT:
        if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
            if (ack != conn->snd_nxt) return;  /* wrong ACK */
            conn->rcv_irs = seq;
            conn->rcv_nxt = seq + 1;
            conn->snd_una = ack;
            conn->snd_wnd = ntohs(hdr->window);
            conn->state = TCP_ESTABLISHED;
            conn->retransmit_count = 0;
            tcp_send_ack(conn);
            pr_info("Connection %d ESTABLISHED\n", idx);
        } else if (flags & TCP_RST) {
            conn->rst_received = 1;
            conn->state = TCP_CLOSED;
        }
        return;

    case TCP_SYN_RECEIVED:
        if (flags & TCP_ACK) {
            /* Use snd_iss+1 instead of snd_nxt: with synchronous loopback,
             * the ACK arrives before snd_nxt is incremented by the caller. */
            if (ack == conn->snd_iss + 1) {
                conn->snd_una = ack;
                conn->snd_nxt = conn->snd_iss + 1;
                conn->state = TCP_ESTABLISHED;
                conn->accepted = 1;
                conn->retransmit_count = 0;
                pr_info("Connection %d ESTABLISHED (accepted)\n", idx);
                /* Process any data piggybacked on the ACK */
                if (payload_len > 0)
                    goto established_data;
            }
        } else if (flags & TCP_RST) {
            conn->rst_received = 1;
            conn->state = TCP_CLOSED;
        }
        return;

    case TCP_ESTABLISHED:
        if (flags & TCP_RST) {
            conn->rst_received = 1;
            conn->state = TCP_CLOSED;
            return;
        }

        /* ACK processing */
        if (flags & TCP_ACK) {
            if (ack > conn->snd_una && ack <= conn->snd_nxt) {
                conn->snd_una = ack;
                conn->retransmit_count = 0;
            }
            conn->snd_wnd = ntohs(hdr->window);
        }

        /* Data */
    established_data:
        if (payload_len > 0) {
            if (seq == conn->rcv_nxt) {
                /* In-order data: copy to rx buffer */
                uint32_t space = TCP_RX_BUF_SIZE - conn->rx_count;
                uint32_t copy = payload_len;
                if (copy > space) copy = space;

                for (uint32_t i = 0; i < copy; i++) {
                    conn->rx_buf[conn->rx_write_pos] = payload[i];
                    conn->rx_write_pos = (conn->rx_write_pos + 1) % TCP_RX_BUF_SIZE;
                }
                /* Barrier + single update so SMP readers see full data */
                arch_memory_barrier();
                conn->rx_count += copy;
                conn->rcv_nxt += copy;
                conn->rx_data_ready = 1;
                tcp_send_ack(conn);
            } else {
                /* Out-of-order: send dup ACK */
                tcp_send_ack(conn);
            }
        }

        /* FIN */
        if (flags & TCP_FIN) {
            conn->rcv_nxt = seq + payload_len + 1;
            conn->fin_received = 1;
            conn->state = TCP_CLOSE_WAIT;
            tcp_send_ack(conn);
        }
        return;

    case TCP_FIN_WAIT_1:
        if (flags & TCP_RST) {
            conn->rst_received = 1;
            conn->state = TCP_CLOSED;
            conn->in_use = 0;
            return;
        }
        if (flags & TCP_ACK) {
            if (ack == conn->snd_nxt) {
                conn->snd_una = ack;
                if (flags & TCP_FIN) {
                    conn->rcv_nxt = seq + payload_len + 1;
                    conn->state = TCP_TIME_WAIT;
                    conn->time_wait_tick = arch_timer_get_ticks() + 36;
                    tcp_send_ack(conn);
                } else {
                    conn->state = TCP_FIN_WAIT_2;
                }
            }
        }
        if ((flags & TCP_FIN) && conn->state == TCP_FIN_WAIT_1) {
            conn->rcv_nxt = seq + payload_len + 1;
            conn->state = TCP_CLOSING;
            tcp_send_ack(conn);
        }
        return;

    case TCP_FIN_WAIT_2:
        if (flags & TCP_FIN) {
            conn->rcv_nxt = seq + payload_len + 1;
            conn->state = TCP_TIME_WAIT;
            conn->time_wait_tick = arch_timer_get_ticks() + 36;
            tcp_send_ack(conn);
        }
        return;

    case TCP_CLOSING:
        if ((flags & TCP_ACK) && ack == conn->snd_nxt) {
            conn->state = TCP_TIME_WAIT;
            conn->time_wait_tick = arch_timer_get_ticks() + 36;
        }
        return;

    case TCP_CLOSE_WAIT:
        /* Handle retransmitted FINs and ACKs while waiting for app close */
        if (flags & TCP_RST) {
            conn->rst_received = 1;
            conn->state = TCP_CLOSED;
            conn->in_use = 0;
            return;
        }
        if (flags & TCP_ACK) {
            if (ack > conn->snd_una && ack <= conn->snd_nxt)
                conn->snd_una = ack;
            conn->snd_wnd = ntohs(hdr->window);
        }
        if (flags & TCP_FIN) {
            /* Retransmitted FIN — re-ACK */
            tcp_send_ack(conn);
        }
        return;

    case TCP_LAST_ACK:
        if ((flags & TCP_ACK) && ack == conn->snd_nxt) {
            conn->state = TCP_CLOSED;
            conn->in_use = 0;
        }
        return;

    case TCP_TIME_WAIT:
        /* Respond to any FIN retransmit */
        if (flags & TCP_FIN) {
            tcp_send_ack(conn);
            conn->time_wait_tick = arch_timer_get_ticks() + 36;
        }
        return;

    default:
        return;
    }
}

/* --- Timer --- */

void tcp_timer_check(void) {
    uint64_t now = arch_timer_get_ticks();

    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (!tcp_conns[i].in_use) continue;
        tcp_conn_t *c = &tcp_conns[i];

        /* Retransmission */
        if (c->tx_buf_len > 0 && c->snd_una < c->snd_nxt && now >= c->rto_tick) {
            if (c->retransmit_count >= 5) {
                pr_err("Connection %d: retransmit limit, RST\n", i);
                tcp_send_segment(c, TCP_RST, 0, 0);
                c->rst_received = 1;
                c->state = TCP_CLOSED;
                c->in_use = 0;
                continue;
            }
            /* Retransmit */
            uint32_t saved_nxt = c->snd_nxt;
            c->snd_nxt = c->tx_buf_seq;
            tcp_send_segment(c, TCP_ACK | TCP_PSH, c->tx_buf, c->tx_buf_len);
            c->snd_nxt = saved_nxt;
            c->retransmit_count++;
            /* Exponential backoff: 18, 36, 72, 144, 288 ticks */
            uint64_t rto = 18;
            for (int r = 0; r < c->retransmit_count; r++)
                rto *= 2;
            c->rto_tick = now + rto;
        }

        /* TIME_WAIT expiry */
        if (c->state == TCP_TIME_WAIT && now >= c->time_wait_tick) {
            c->state = TCP_CLOSED;
            c->in_use = 0;
        }
    }
}

/* --- Syscall-facing API --- */

int tcp_socket(void) {
    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (!tcp_conns[i].in_use) {
            tcp_conn_t *c = &tcp_conns[i];
            tcp_memset(c, 0, sizeof(tcp_conn_t));
            c->in_use = 1;
            c->state = TCP_CLOSED;
            c->local_ip = 0x0A00020FU;  /* 10.0.2.15 */
            c->local_port = tcp_ephemeral_port++;
            c->rcv_wnd = TCP_WINDOW;
            return i;
        }
    }
    /* All slots occupied — try to reclaim a TIME_WAIT slot */
    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (tcp_conns[i].in_use && tcp_conns[i].state == TCP_TIME_WAIT) {
            tcp_conn_t *c = &tcp_conns[i];
            tcp_memset(c, 0, sizeof(tcp_conn_t));
            c->in_use = 1;
            c->state = TCP_CLOSED;
            c->local_ip = 0x0A00020FU;
            c->local_port = tcp_ephemeral_port++;
            c->rcv_wnd = TCP_WINDOW;
            return i;
        }
    }
    return -ENOMEM;
}

int tcp_connect(int conn_idx, uint32_t remote_ip, uint16_t remote_port) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use || c->state != TCP_CLOSED) return -EINVAL;

    c->remote_ip = remote_ip;
    c->remote_port = remote_port;

    c->snd_iss = tcp_gen_isn(conn_idx);
    c->snd_nxt = c->snd_iss;
    c->snd_una = c->snd_iss;

    /* Send SYN */
    c->state = TCP_SYN_SENT;
    tcp_send_segment(c, TCP_SYN, 0, 0);
    c->snd_nxt = c->snd_iss + 1;
    c->rto_tick = arch_timer_get_ticks() + 18;
    c->retransmit_count = 0;

    /* Save SYN for retransmit (zero-length, just flags) */
    c->tx_buf_len = 0;
    c->tx_buf_seq = c->snd_iss;

    /* Non-blocking: return immediately after sending SYN */
    if (c->nonblock)
        return -115;  /* EINPROGRESS */

    /* Yield loop until ESTABLISHED or failure */
    int timeout = 10000;
    while (c->state == TCP_SYN_SENT && !c->rst_received) {
        tcp_timer_check();
        if (--timeout <= 0) {
            c->state = TCP_CLOSED;
            c->in_use = 0;
            return -ETIMEDOUT;
        }
        if (sched_has_pending_signal()) return -EINTR;
        sched_yield();
    }

    if (c->state != TCP_ESTABLISHED) {
        c->state = TCP_CLOSED;
        c->in_use = 0;
        return -ECONNREFUSED;
    }

    c->tx_buf_len = 0;  /* clear retransmit buffer */
    return 0;
}

int tcp_listen(int conn_idx, uint16_t port) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use) return -EBADF;

    c->local_port = port;
    c->state = TCP_LISTEN;

    for (int i = 0; i < TCP_BACKLOG_SIZE; i++)
        c->backlog[i].valid = 0;

    return 0;
}

int tcp_accept(int listen_idx) {
    if (listen_idx < 0 || listen_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *lc = &tcp_conns[listen_idx];
    if (!lc->in_use || lc->state != TCP_LISTEN) return -EINVAL;

    /* Wait for backlog entry */
    int timeout = 50000;
    tcp_backlog_entry_t entry;
    int found = 0;

    while (!found) {
        for (int i = 0; i < TCP_BACKLOG_SIZE; i++) {
            if (lc->backlog[i].valid) {
                entry = lc->backlog[i];
                lc->backlog[i].valid = 0;
                found = 1;
                break;
            }
        }
        if (!found) {
            if (lc->nonblock) return -EAGAIN;
            tcp_timer_check();
            if (--timeout <= 0) return -ETIMEDOUT;
            if (sched_has_pending_signal()) return -EINTR;
            sched_yield();
        }
    }

    /* Allocate new connection for the accepted client */
    int new_idx = -1;
    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (!tcp_conns[i].in_use) {
            new_idx = i;
            break;
        }
    }
    /* Reclaim a TIME_WAIT slot if no free slots available */
    if (new_idx < 0) {
        for (int i = 0; i < MAX_TCP_CONNS; i++) {
            if (tcp_conns[i].in_use && tcp_conns[i].state == TCP_TIME_WAIT) {
                tcp_conns[i].state = TCP_CLOSED;
                tcp_conns[i].in_use = 0;
                new_idx = i;
                break;
            }
        }
    }
    if (new_idx < 0) return -ENOMEM;

    tcp_conn_t *nc = &tcp_conns[new_idx];
    tcp_memset(nc, 0, sizeof(tcp_conn_t));
    nc->in_use = 1;
    nc->state = TCP_SYN_RECEIVED;
    nc->local_ip = lc->local_ip;
    nc->local_port = lc->local_port;
    nc->remote_ip = entry.remote_ip;
    nc->remote_port = entry.remote_port;
    nc->rcv_irs = entry.remote_seq;
    nc->rcv_nxt = entry.remote_seq + 1;
    nc->rcv_wnd = TCP_WINDOW;

    /* Generate ISN and send SYN-ACK */
    nc->snd_iss = tcp_gen_isn(new_idx);
    nc->snd_nxt = nc->snd_iss;
    nc->snd_una = nc->snd_iss;

    tcp_send_segment(nc, TCP_SYN | TCP_ACK, 0, 0);
    nc->snd_nxt = nc->snd_iss + 1;
    nc->rto_tick = arch_timer_get_ticks() + 18;

    /* Wait for ESTABLISHED */
    timeout = 10000;
    while (nc->state == TCP_SYN_RECEIVED && !nc->rst_received) {
        tcp_timer_check();
        if (--timeout <= 0) {
            nc->state = TCP_CLOSED;
            nc->in_use = 0;
            return -ETIMEDOUT;
        }
        if (sched_has_pending_signal()) return -EINTR;
        sched_yield();
    }

    /* Accept CLOSE_WAIT too: with SMP loopback, the remote side can
     * connect, send, and close before we check, transitioning the
     * connection past ESTABLISHED into CLOSE_WAIT. */
    if (nc->state != TCP_ESTABLISHED && nc->state != TCP_CLOSE_WAIT) {
        nc->state = TCP_CLOSED;
        nc->in_use = 0;
        return -ECONNREFUSED;
    }

    nc->tx_buf_len = 0;
    return new_idx;
}

int64_t tcp_send(int conn_idx, const uint8_t *buf, uint32_t len) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use || c->state != TCP_ESTABLISHED) return -ENOTCONN;
    if (c->rst_received) return -ENOTCONN;

    if (len > TCP_MSS) len = TCP_MSS;

    /* Save for retransmit */
    tcp_memcpy(c->tx_buf, buf, len);
    c->tx_buf_len = len;
    c->tx_buf_seq = c->snd_nxt;

    /* Increment snd_nxt before sending so loopback ACKs (which arrive
     * synchronously) see the correct range.  Temporarily restore the
     * old value so tcp_send_segment puts the right seq in the header. */
    uint32_t orig_nxt = c->snd_nxt;
    c->snd_nxt += len;
    uint32_t new_nxt = c->snd_nxt;
    c->snd_nxt = orig_nxt;
    tcp_send_segment(c, TCP_ACK | TCP_PSH, buf, len);
    c->snd_nxt = new_nxt;
    c->rto_tick = arch_timer_get_ticks() + 18;
    c->retransmit_count = 0;

    return (int64_t)len;
}

int64_t tcp_recv(int conn_idx, uint8_t *buf, uint32_t len) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use) return -EBADF;

    /* Non-blocking: return immediately if no data */
    if (c->nonblock && c->rx_count == 0 && !c->fin_received && !c->rst_received)
        return -EAGAIN;

    /* Yield until data, FIN, or RST */
    int timeout = 50000;
    while (c->rx_count == 0 && !c->fin_received && !c->rst_received) {
        tcp_timer_check();
        if (--timeout <= 0) return -ETIMEDOUT;
        if (sched_has_pending_signal()) return -EINTR;
        sched_yield();
    }

    if (c->rst_received) return -ENOTCONN;

    if (c->rx_count == 0) {
        return 0;  /* EOF (FIN received, no data) */
    }

    uint32_t copy = len;
    if (copy > c->rx_count) copy = c->rx_count;

    uint16_t old_wnd = tcp_calc_rcv_wnd(c);

    for (uint32_t i = 0; i < copy; i++) {
        buf[i] = c->rx_buf[c->rx_read_pos];
        c->rx_read_pos = (c->rx_read_pos + 1) % TCP_RX_BUF_SIZE;
        c->rx_count--;
    }

    if (c->rx_count == 0)
        c->rx_data_ready = 0;

    /* Send window update ACK if window grew from near-zero to >= MSS */
    if (old_wnd < TCP_MSS && tcp_calc_rcv_wnd(c) >= TCP_MSS &&
        c->state == TCP_ESTABLISHED)
        tcp_send_ack(c);

    return (int64_t)copy;
}

int tcp_close(int conn_idx) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use) return -EBADF;

    if (c->state == TCP_ESTABLISHED) {
        /* Set state and increment snd_nxt BEFORE sending so that
         * synchronous loopback ACKs are handled in the correct state.
         * Use save/restore to keep the correct seq in the FIN header. */
        uint32_t fin_seq = c->snd_nxt;
        c->snd_nxt = fin_seq + 1;
        c->state = TCP_FIN_WAIT_1;
        c->rto_tick = arch_timer_get_ticks() + 18;
        c->retransmit_count = 0;
        c->tx_buf_len = 0;
        c->tx_buf_seq = fin_seq;

        uint32_t saved_nxt = c->snd_nxt;
        c->snd_nxt = fin_seq;
        tcp_send_segment(c, TCP_FIN | TCP_ACK, 0, 0);
        c->snd_nxt = saved_nxt;

        /* Nonblock: send FIN and return, let state machine finish async */
        if (c->nonblock) {
            /* If loopback already completed the close, clean up */
            if (c->state == TCP_CLOSED) { c->in_use = 0; }
            return 0;
        }

        /* Yield until closed */
        int timeout = 10000;
        while (c->state != TCP_CLOSED && c->state != TCP_TIME_WAIT) {
            tcp_timer_check();
            if (--timeout <= 0) break;
            sched_yield();
        }
    } else if (c->state == TCP_CLOSE_WAIT) {
        /* Same save/restore pattern for CLOSE_WAIT → LAST_ACK */
        uint32_t fin_seq = c->snd_nxt;
        c->snd_nxt = fin_seq + 1;
        c->state = TCP_LAST_ACK;
        c->rto_tick = arch_timer_get_ticks() + 18;
        c->retransmit_count = 0;
        c->tx_buf_len = 0;
        c->tx_buf_seq = fin_seq;

        uint32_t saved_nxt = c->snd_nxt;
        c->snd_nxt = fin_seq;
        tcp_send_segment(c, TCP_FIN | TCP_ACK, 0, 0);
        c->snd_nxt = saved_nxt;

        /* Nonblock: send FIN and return, let state machine finish async */
        if (c->nonblock) {
            if (c->state == TCP_CLOSED) { c->in_use = 0; }
            return 0;
        }

        int timeout = 10000;
        while (c->state == TCP_LAST_ACK) {
            tcp_timer_check();
            if (--timeout <= 0) break;
            sched_yield();
        }
    }

    /* If TIME_WAIT, leave for timer to clean up. Otherwise force close. */
    if (c->state != TCP_TIME_WAIT) {
        c->state = TCP_CLOSED;
        c->in_use = 0;
    }

    return 0;
}

int tcp_set_nonblock(int conn_idx, int nb) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return -EBADF;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use) return -EBADF;
    c->nonblock = nb ? 1 : 0;
    return 0;
}

int tcp_poll(int conn_idx) {
    if (conn_idx < 0 || conn_idx >= MAX_TCP_CONNS) return 0;
    tcp_conn_t *c = &tcp_conns[conn_idx];
    if (!c->in_use) return POLLERR;

    int events = 0;

    /* Listener: readable when backlog has a pending connection */
    if (c->state == TCP_LISTEN) {
        for (int i = 0; i < TCP_BACKLOG_SIZE; i++) {
            if (c->backlog[i].valid) { events |= POLLIN; break; }
        }
        return events;
    }

    /* Readable: data available or FIN received */
    if (c->rx_count > 0 || c->fin_received)
        events |= POLLIN;

    /* Writable: established and not reset */
    if (c->state == TCP_ESTABLISHED && !c->rst_received)
        events |= POLLOUT;

    /* Error/hangup */
    if (c->rst_received) events |= POLLERR;
    if (c->fin_received) events |= POLLHUP;

    return events;
}
