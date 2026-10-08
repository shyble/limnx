#define pr_fmt(fmt) "[net]  " fmt
#include "klog.h"
#include "net/net.h"
#include "net/virtio_net.h"
#include "arch/serial.h"
#include "sched/sched.h"
#include "errno.h"
#include "arch/cpu.h"

/* --- Configuration (QEMU user-mode networking) --- */

#define NET_IP      0x0A00020FU  /* 10.0.2.15 */
#define NET_GW      0x0A000202U  /* 10.0.2.2  */
#define NET_MASK    0xFFFFFF00U  /* /24       */
#define LOOPBACK_NET 0x7F000000U /* 127.0.0.0/8 */

static uint8_t our_mac[ETH_ALEN];
static uint32_t our_ip;
static uint32_t gw_ip;

/* --- ARP table --- */

#define ARP_TABLE_SIZE 16

typedef struct {
    uint32_t ip;
    uint8_t  mac[ETH_ALEN];
    int      valid;
} arp_entry_t;

static arp_entry_t arp_table[ARP_TABLE_SIZE];

/* --- Socket table --- */

static socket_t sockets[MAX_SOCKETS];

/* --- ICMP ping tracking --- */

static volatile int ping_reply_received;

/* --- Utility --- */

static void memcpy_net(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++)
        d[i] = s[i];
}

static void memset_net(void *dst, uint8_t val, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (uint32_t i = 0; i < n; i++)
        d[i] = val;
}

uint16_t ip_checksum(const void *data, uint32_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)ptr;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/* --- Ethernet TX --- */

static int eth_tx(const uint8_t dst[ETH_ALEN], uint16_t ethertype,
                  const void *payload, uint32_t payload_len) {
    uint8_t frame[ETH_HLEN + 1500];
    if (payload_len > 1500) return -EMSGSIZE;

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memcpy_net(eth->dst, dst, ETH_ALEN);
    memcpy_net(eth->src, our_mac, ETH_ALEN);
    eth->ethertype = htons(ethertype);
    memcpy_net(frame + ETH_HLEN, payload, payload_len);

    return virtio_net_tx(frame, ETH_HLEN + payload_len);
}

/* --- ARP --- */

static arp_entry_t *arp_lookup(uint32_t ip) {
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (arp_table[i].valid && arp_table[i].ip == ip)
            return &arp_table[i];
    }
    return 0;
}

static void arp_learn(uint32_t ip, const uint8_t mac_addr[ETH_ALEN]) {
    /* Update existing */
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (arp_table[i].valid && arp_table[i].ip == ip) {
            memcpy_net(arp_table[i].mac, mac_addr, ETH_ALEN);
            return;
        }
    }
    /* Add new */
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (!arp_table[i].valid) {
            arp_table[i].ip = ip;
            memcpy_net(arp_table[i].mac, mac_addr, ETH_ALEN);
            arp_table[i].valid = 1;
            return;
        }
    }
}

static void arp_send_request(uint32_t target_ip) {
    arp_pkt_t pkt;
    pkt.hw_type    = htons(1);       /* Ethernet */
    pkt.proto_type = htons(0x0800);  /* IPv4 */
    pkt.hw_len     = 6;
    pkt.proto_len  = 4;
    pkt.opcode     = htons(ARP_OP_REQUEST);

    memcpy_net(pkt.sender_mac, our_mac, ETH_ALEN);
    pkt.sender_ip = htonl(our_ip);
    memset_net(pkt.target_mac, 0, ETH_ALEN);
    pkt.target_ip = htonl(target_ip);

    uint8_t bcast[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    eth_tx(bcast, ETH_TYPE_ARP, &pkt, sizeof(pkt));
}

static void arp_send_reply(uint32_t target_ip, const uint8_t target_mac[ETH_ALEN]) {
    arp_pkt_t pkt;
    pkt.hw_type    = htons(1);
    pkt.proto_type = htons(0x0800);
    pkt.hw_len     = 6;
    pkt.proto_len  = 4;
    pkt.opcode     = htons(ARP_OP_REPLY);

    memcpy_net(pkt.sender_mac, our_mac, ETH_ALEN);
    pkt.sender_ip = htonl(our_ip);
    memcpy_net(pkt.target_mac, target_mac, ETH_ALEN);
    pkt.target_ip = htonl(target_ip);

    eth_tx(target_mac, ETH_TYPE_ARP, &pkt, sizeof(pkt));
}

static void handle_arp(const uint8_t *data, uint32_t len) {
    if (len < sizeof(arp_pkt_t)) return;
    const arp_pkt_t *arp = (const arp_pkt_t *)data;

    uint16_t op = ntohs(arp->opcode);
    uint32_t sender_ip = ntohl(arp->sender_ip);
    uint32_t target_ip = ntohl(arp->target_ip);

    /* Learn sender */
    arp_learn(sender_ip, arp->sender_mac);

    if (op == ARP_OP_REQUEST && target_ip == our_ip) {
        pr_info("ARP: who-has %x? Replying\n", target_ip);
        arp_send_reply(sender_ip, arp->sender_mac);
    } else if (op == ARP_OP_REPLY) {
        pr_info("ARP: reply from %x\n", sender_ip);
    }
}

/* Resolve IP → MAC. Sends ARP request and spins briefly waiting for reply. */
static int arp_resolve(uint32_t ip, uint8_t mac_out[ETH_ALEN]) {
    /* If not on our subnet, use gateway */
    if ((ip & NET_MASK) != (our_ip & NET_MASK))
        ip = gw_ip;

    arp_entry_t *e = arp_lookup(ip);
    if (e) {
        memcpy_net(mac_out, e->mac, ETH_ALEN);
        return 0;
    }

    /* Send request and busy-wait */
    for (int attempt = 0; attempt < 5; attempt++) {
        arp_send_request(ip);
        /* Spin for ~50ms worth of yields */
        for (int i = 0; i < 500; i++) {
            e = arp_lookup(ip);
            if (e) {
                memcpy_net(mac_out, e->mac, ETH_ALEN);
                return 0;
            }
            sched_yield();
        }
    }

    pr_err("ARP: failed to resolve %x\n", ip);
    return -ETIMEDOUT;
}

/* --- IPv4 --- */

static uint16_t ip_id_counter = 1;

/* Forward declaration for loopback path */
static void handle_ipv4(const uint8_t *data, uint32_t len);

/* Check if dst_ip is a loopback target (our own IP or 127.x.x.x) */
static int is_loopback(uint32_t dst_ip) {
    return (dst_ip == our_ip) || ((dst_ip & 0xFF000000) == LOOPBACK_NET);
}

int net_tx_ipv4(uint32_t dst_ip, uint8_t protocol,
                 const void *payload, uint32_t payload_len) {
    uint8_t pkt[1500];
    ipv4_hdr_t *ip = (ipv4_hdr_t *)pkt;

    ip->ver_ihl    = 0x45;  /* version 4, IHL=5 (20 bytes) */
    ip->tos        = 0;
    ip->total_len  = htons(20 + payload_len);
    ip->id         = htons(ip_id_counter++);
    ip->flags_frag = 0;
    ip->ttl        = 64;
    ip->protocol   = protocol;
    ip->checksum   = 0;
    ip->src_ip     = htonl(our_ip);
    ip->dst_ip     = htonl(dst_ip);
    ip->checksum   = ip_checksum(ip, 20);

    memcpy_net(pkt + 20, payload, payload_len);

    uint32_t total = 20 + payload_len;

    /* Software loopback: if sending to ourselves, feed directly to RX path */
    if (is_loopback(dst_ip)) {
        handle_ipv4(pkt, total);
        return 0;
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_resolve(dst_ip, dst_mac) != 0)
        return -ETIMEDOUT;

    return eth_tx(dst_mac, ETH_TYPE_IPV4, pkt, total);
}

/* --- ICMP --- */

static void handle_icmp(uint32_t src_ip, const uint8_t *data, uint32_t len) {
    if (len < sizeof(icmp_hdr_t)) return;
    const icmp_hdr_t *icmp = (const icmp_hdr_t *)data;

    if (icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        pr_info("ICMP: echo request from %x\n", src_ip);
        /* Build reply: same data, change type to 0 */
        uint8_t reply[1500];
        if (len > 1500) return;
        memcpy_net(reply, data, len);
        icmp_hdr_t *r = (icmp_hdr_t *)reply;
        r->type = ICMP_TYPE_ECHO_REPLY;
        r->checksum = 0;
        r->checksum = ip_checksum(reply, len);
        net_tx_ipv4(src_ip, IP_PROTO_ICMP, reply, len);
    } else if (icmp->type == ICMP_TYPE_ECHO_REPLY) {
        pr_info("ICMP: echo reply from %x\n", src_ip);
        ping_reply_received = 1;
    }
}

int net_send_ping(uint32_t dst_ip) {
    ping_reply_received = 0;

    uint8_t pkt[64];
    icmp_hdr_t *icmp = (icmp_hdr_t *)pkt;
    icmp->type     = ICMP_TYPE_ECHO_REQUEST;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = htons(1);
    icmp->seq      = htons(1);

    /* Fill payload with pattern */
    for (int i = sizeof(icmp_hdr_t); i < 64; i++)
        pkt[i] = (uint8_t)i;

    icmp->checksum = ip_checksum(pkt, 64);

    return net_tx_ipv4(dst_ip, IP_PROTO_ICMP, pkt, 64);
}

int net_got_ping_reply(void) {
    return ping_reply_received;
}

/* --- UDP --- */

static void handle_udp(uint32_t src_ip, const uint8_t *data, uint32_t len) {
    if (len < sizeof(udp_hdr_t)) return;
    const udp_hdr_t *udp = (const udp_hdr_t *)data;

    uint16_t dst_port = ntohs(udp->dst_port);
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t udp_len  = ntohs(udp->length);

    if (udp_len < 8 || udp_len > len) return;
    uint32_t payload_len = udp_len - 8;
    const uint8_t *payload = data + 8;

    /* Demux to socket */
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (sockets[i].in_use && sockets[i].local_port == dst_port) {
            if (!sockets[i].rx_ready) {
                uint32_t copy_len = payload_len;
                if (copy_len > SOCKET_BUF_SIZE) copy_len = SOCKET_BUF_SIZE;
                memcpy_net(sockets[i].rx_buf, payload, copy_len);
                sockets[i].rx_len = copy_len;
                sockets[i].rx_src_ip = src_ip;
                sockets[i].rx_src_port = src_port;
                arch_memory_barrier();
                sockets[i].rx_ready = 1;
            }
            return;
        }
    }
}

static void handle_ipv4(const uint8_t *data, uint32_t len) {
    if (len < 20) return;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)data;

    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || ihl > len) return;

    /* Verify checksum */
    if (ip_checksum(data, ihl) != 0) return;

    uint16_t total = ntohs(ip->total_len);
    if (total > len || total < ihl) return;

    uint32_t src_ip = ntohl(ip->src_ip);
    uint32_t dst_ip = ntohl(ip->dst_ip);

    /* Only accept packets for us, broadcast, or loopback */
    if (dst_ip != our_ip && dst_ip != 0xFFFFFFFF &&
        (dst_ip & 0xFF000000) != LOOPBACK_NET)
        return;

    const uint8_t *payload = data + ihl;
    uint32_t payload_len = total - ihl;

    if (ip->protocol == IP_PROTO_ICMP) {
        handle_icmp(src_ip, payload, payload_len);
    } else if (ip->protocol == IP_PROTO_TCP) {
        extern void tcp_rx(uint32_t src_ip, uint32_t dst_ip,
                           const uint8_t *data, uint32_t len);
        tcp_rx(src_ip, dst_ip, payload, payload_len);
    } else if (ip->protocol == IP_PROTO_UDP) {
        handle_udp(src_ip, payload, payload_len);
    }
}

/* --- Ethernet RX (called from virtio_net IRQ handler) --- */

void net_rx(const void *frame, uint32_t len) {
    if (len < ETH_HLEN) return;

    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    uint16_t ethertype = ntohs(eth->ethertype);
    const uint8_t *payload = (const uint8_t *)frame + ETH_HLEN;
    uint32_t payload_len = len - ETH_HLEN;

    if (ethertype == ETH_TYPE_ARP) {
        handle_arp(payload, payload_len);
    } else if (ethertype == ETH_TYPE_IPV4) {
        handle_ipv4(payload, payload_len);
    }
}

/* --- Socket API --- */

int net_socket(void) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (!sockets[i].in_use) {
            sockets[i].in_use = 1;
            sockets[i].local_port = 0;
            sockets[i].rx_ready = 0;
            sockets[i].rx_len = 0;
            return i;
        }
    }
    return -ENOMEM;
}

int net_bind(int sockfd, uint16_t port) {
    if (sockfd < 0 || sockfd >= MAX_SOCKETS) return -EBADF;
    if (!sockets[sockfd].in_use) return -EBADF;

    /* Check port not already bound */
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (sockets[i].in_use && sockets[i].local_port == port)
            return -EADDRINUSE;
    }

    sockets[sockfd].local_port = port;
    return 0;
}

int net_sendto(int sockfd, const void *buf, uint32_t len,
               uint32_t dst_ip, uint16_t dst_port) {
    if (sockfd < 0 || sockfd >= MAX_SOCKETS) return -EBADF;
    if (!sockets[sockfd].in_use) return -EBADF;
    if (len > 1472) return -EMSGSIZE; /* max UDP payload */

    uint8_t pkt[8 + 1472];
    udp_hdr_t *udp = (udp_hdr_t *)pkt;
    udp->src_port = htons(sockets[sockfd].local_port);
    udp->dst_port = htons(dst_port);
    udp->length   = htons(8 + len);
    udp->checksum = 0; /* checksum optional for IPv4 UDP */

    memcpy_net(pkt + 8, buf, len);

    return net_tx_ipv4(dst_ip, IP_PROTO_UDP, pkt, 8 + len);
}

int net_recvfrom(int sockfd, void *buf, uint32_t len,
                 uint32_t *src_ip, uint16_t *src_port) {
    if (sockfd < 0 || sockfd >= MAX_SOCKETS) return -EBADF;
    if (!sockets[sockfd].in_use) return -EBADF;

    /* Busy-wait with yield until data arrives (timeout after ~5000 yields) */
    int timeout = 5000;
    while (!sockets[sockfd].rx_ready) {
        if (--timeout <= 0)
            return -ETIMEDOUT;  /* timed out */
        if (sched_has_pending_signal()) return -EINTR;
        sched_yield();
    }

    uint32_t copy_len = sockets[sockfd].rx_len;
    if (copy_len > len) copy_len = len;

    memcpy_net(buf, sockets[sockfd].rx_buf, copy_len);
    if (src_ip)   *src_ip   = sockets[sockfd].rx_src_ip;
    if (src_port) *src_port = sockets[sockfd].rx_src_port;

    sockets[sockfd].rx_ready = 0;
    return (int)copy_len;
}

uint32_t net_get_our_ip(void) {
    return our_ip;
}

/* --- Init --- */

void net_init(void) {
    virtio_net_get_mac(our_mac);
    our_ip = NET_IP;
    gw_ip  = NET_GW;

    /* Clear socket table */
    for (int i = 0; i < MAX_SOCKETS; i++)
        sockets[i].in_use = 0;

    /* Clear ARP table */
    for (int i = 0; i < ARP_TABLE_SIZE; i++)
        arp_table[i].valid = 0;

    ping_reply_received = 0;

    pr_info("IP=%u.%u.%u.%u  GW=%u.%u.%u.%u\n",
        (our_ip >> 24) & 0xFF, (our_ip >> 16) & 0xFF,
        (our_ip >>  8) & 0xFF, our_ip & 0xFF,
        (gw_ip >> 24) & 0xFF, (gw_ip >> 16) & 0xFF,
        (gw_ip >>  8) & 0xFF, gw_ip & 0xFF);
    pr_info("Network stack initialized\n");
}
