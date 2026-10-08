#ifndef LIMNX_TCP_H
#define LIMNX_TCP_H

#include <stdint.h>

#define MAX_TCP_CONNS    32
#define TCP_RX_BUF_SIZE  8192
#define TCP_MSS          1460
#define TCP_WINDOW       8192
#define TCP_BACKLOG_SIZE 4

enum tcp_state {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_TIME_WAIT,
    TCP_CLOSING
};

typedef struct tcp_backlog_entry {
    uint32_t remote_ip;
    uint16_t remote_port;
    uint32_t remote_seq;
    int      valid;
} tcp_backlog_entry_t;

typedef struct tcp_conn {
    int            in_use;
    enum tcp_state state;

    /* 4-tuple */
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;

    /* Sequence numbers */
    uint32_t snd_una;       /* oldest unacked */
    uint32_t snd_nxt;       /* next to send */
    uint32_t snd_iss;       /* initial send seq */
    uint32_t rcv_nxt;       /* next expected */
    uint32_t rcv_irs;       /* initial recv seq */

    /* Circular receive buffer */
    uint8_t  rx_buf[TCP_RX_BUF_SIZE];
    uint32_t rx_read_pos;
    uint32_t rx_write_pos;
    uint32_t rx_count;

    /* Retransmission: save last sent segment */
    uint8_t  tx_buf[TCP_MSS];
    uint32_t tx_buf_len;
    uint32_t tx_buf_seq;
    uint64_t rto_tick;          /* PIT tick when retransmit fires */
    uint8_t  retransmit_count;

    /* Window */
    uint16_t snd_wnd;
    uint16_t rcv_wnd;

    /* Listen backlog */
    tcp_backlog_entry_t backlog[TCP_BACKLOG_SIZE];

    /* Flags */
    volatile int rx_data_ready;
    volatile int accepted;
    volatile int fin_received;
    volatile int rst_received;
    uint8_t nonblock;

    uint64_t time_wait_tick;
} tcp_conn_t;

void tcp_init(void);
void tcp_rx(uint32_t src_ip, uint32_t dst_ip, const uint8_t *data, uint32_t len);
void tcp_timer_check(void);

/* Syscall-facing API */
int     tcp_socket(void);
int     tcp_connect(int conn_idx, uint32_t remote_ip, uint16_t remote_port);
int     tcp_listen(int conn_idx, uint16_t port);
int     tcp_accept(int listen_idx);
int64_t tcp_send(int conn_idx, const uint8_t *buf, uint32_t len);
int64_t tcp_recv(int conn_idx, uint8_t *buf, uint32_t len);
int     tcp_close(int conn_idx);
int     tcp_set_nonblock(int conn_idx, int nb);
int     tcp_poll(int conn_idx);

#endif
