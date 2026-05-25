/*
 * inferd_proxy.c — Network inference proxy for Limnx
 *
 * Registers as an inference service, accepts requests via unix socket,
 * forwards them over TCP to a remote llama-server (or compatible HTTP API).
 *
 * Usage: inferd_proxy <host_ip> <port> [svc_name] [sock_path]
 *
 * Compatible with:
 *   - llama.cpp's llama-server (/completion endpoint)
 *   - Any OpenAI-compatible server (/v1/completions)
 *
 * Host-side: llama-server -m model.gguf --port 9200 --host 0.0.0.0
 */

#include "libc/libc.h"

#define MAX_PROMPT  2048
#define MAX_RESP    8192

static uint32_t remote_ip;
static uint16_t remote_port;

/* Parse "A.B.C.D" → uint32_t IP */
static uint32_t parse_ip(const char *s) {
    uint32_t a = 0, b = 0, c = 0, d = 0;
    int field = 0;
    uint32_t val = 0;
    for (int i = 0; s[i]; i++) {
        if (s[i] == '.') {
            if (field == 0) a = val;
            else if (field == 1) b = val;
            else if (field == 2) c = val;
            val = 0;
            field++;
        } else {
            val = val * 10 + (s[i] - '0');
        }
    }
    d = val;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/* Escape a string for JSON (handle \n, \r, \t, \", \\) */
static int json_escape(const char *src, uint32_t src_len,
                       char *dst, uint32_t dst_max) {
    uint32_t di = 0;
    for (uint32_t i = 0; i < src_len && di < dst_max - 2; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            dst[di++] = '\\'; dst[di++] = c;
        } else if (c == '\n') {
            dst[di++] = '\\'; dst[di++] = 'n';
        } else if (c == '\r') {
            dst[di++] = '\\'; dst[di++] = 'r';
        } else if (c == '\t') {
            dst[di++] = '\\'; dst[di++] = 't';
        } else {
            dst[di++] = c;
        }
    }
    dst[di] = '\0';
    return (int)di;
}

/* Find "content":" in JSON response and extract the string value */
static int extract_content(const char *json, uint32_t json_len,
                           char *out, uint32_t max_out) {
    /* Find "content":" */
    const char *key = "\"content\":\"";
    int klen = 11;
    const char *p = (const char *)0;
    for (uint32_t i = 0; i + klen < json_len; i++) {
        int match = 1;
        for (int k = 0; k < klen; k++) {
            if (json[i + k] != key[k]) { match = 0; break; }
        }
        if (match) { p = &json[i + klen]; break; }
    }
    /* Also try with space: "content": " */
    if (!p) {
        const char *key2 = "\"content\": \"";
        int k2len = 12;
        for (uint32_t i = 0; i + k2len < json_len; i++) {
            int match = 1;
            for (int k = 0; k < k2len; k++) {
                if (json[i + k] != key2[k]) { match = 0; break; }
            }
            if (match) { p = &json[i + k2len]; break; }
        }
    }
    if (!p) return -1;

    /* Extract until closing quote (handle escapes) */
    uint32_t oi = 0;
    while (*p && *p != '"' && oi < max_out - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            if (*p == 'n') out[oi++] = '\n';
            else if (*p == 'r') out[oi++] = '\r';
            else if (*p == 't') out[oi++] = '\t';
            else out[oi++] = *p;
        } else {
            out[oi++] = *p;
        }
        p++;
    }
    out[oi] = '\0';
    return (int)oi;
}

/* Forward a prompt to llama-server via HTTP POST /completion */
static int forward_request(const char *prompt, uint32_t prompt_len,
                           char *response, uint32_t max_resp) {
    long conn = sys_tcp_socket();
    if (conn < 0) {
        printf("[proxy] Failed to create TCP socket\n");
        return -1;
    }

    if (sys_tcp_connect(conn, remote_ip, remote_port) < 0) {
        printf("[proxy] Failed to connect to %lx:%u\n",
               (unsigned long)remote_ip, remote_port);
        sys_tcp_close(conn);
        return -1;
    }

    /* Build JSON body: {"prompt":"...","n_predict":256,"temperature":0.8} */
    char escaped[MAX_PROMPT * 2];
    json_escape(prompt, prompt_len, escaped, sizeof(escaped));

    char body[MAX_PROMPT * 2 + 128];
    int body_len = 0;
    const char *pre = "{\"prompt\":\"";
    while (*pre) body[body_len++] = *pre++;
    for (int i = 0; escaped[i]; i++) body[body_len++] = escaped[i];
    const char *post = "\",\"n_predict\":256,\"temperature\":0.8,\"top_k\":40}";
    while (*post) body[body_len++] = *post++;
    body[body_len] = '\0';

    /* Build HTTP request */
    char http_req[MAX_PROMPT * 2 + 256];
    int hlen = 0;
    const char *h1 = "POST /completion HTTP/1.1\r\nHost: localhost\r\n"
                     "Content-Type: application/json\r\nConnection: close\r\n"
                     "Content-Length: ";
    while (*h1) http_req[hlen++] = *h1++;

    /* itoa for content-length */
    char cl_str[16];
    int ci = 0;
    int tmp = body_len;
    if (tmp == 0) cl_str[ci++] = '0';
    else {
        char rev[16]; int ri = 0;
        while (tmp > 0) { rev[ri++] = '0' + (tmp % 10); tmp /= 10; }
        while (ri > 0) cl_str[ci++] = rev[--ri];
    }
    cl_str[ci] = '\0';
    for (int i = 0; cl_str[i]; i++) http_req[hlen++] = cl_str[i];

    const char *h2 = "\r\n\r\n";
    while (*h2) http_req[hlen++] = *h2++;

    /* Append body */
    for (int i = 0; i < body_len; i++) http_req[hlen++] = body[i];

    /* Send HTTP request */
    sys_tcp_send(conn, http_req, hlen);

    /* Receive HTTP response — keep reading until connection closes
     * or we detect end of JSON body */
    char recv_buf[MAX_RESP];
    uint32_t total = 0;
    int attempts = 0;
    while (total < sizeof(recv_buf) - 1 && attempts < 500) {
        long n = sys_tcp_recv(conn, recv_buf + total, sizeof(recv_buf) - total - 1);
        if (n > 0) {
            total += (uint32_t)n;
            recv_buf[total] = '\0';
            attempts = 0;  /* reset on progress */

            /* Check if we have complete HTTP response with JSON body */
            char *body_start = (char *)0;
            for (uint32_t i = 0; i + 3 < total; i++) {
                if (recv_buf[i] == '\r' && recv_buf[i+1] == '\n' &&
                    recv_buf[i+2] == '\r' && recv_buf[i+3] == '\n') {
                    body_start = &recv_buf[i + 4];
                    break;
                }
            }
            if (body_start) {
                /* Count braces to detect complete JSON */
                int depth = 0;
                for (char *p = body_start; *p; p++) {
                    if (*p == '{') depth++;
                    else if (*p == '}') depth--;
                }
                if (depth == 0 && body_start[0] == '{')
                    break;  /* Complete JSON received */
            }
        } else {
            attempts++;
            sys_yield();
        }
    }

    sys_tcp_close(conn);
    recv_buf[total] = '\0';

    printf("[proxy] recv %u bytes\n", total);
    if (total > 0 && total < 200)
        printf("[proxy] raw: %s\n", recv_buf);
    else if (total >= 200)
        printf("[proxy] first 200: %.200s\n", recv_buf);

    if (total == 0) return -1;

    /* Extract "content" from JSON response */
    int clen = extract_content(recv_buf, total, response, max_resp);
    if (clen <= 0) {
        /* Fallback: return raw body */
        char *body_start = recv_buf;
        for (uint32_t i = 0; i + 3 < total; i++) {
            if (recv_buf[i] == '\r' && recv_buf[i+1] == '\n' &&
                recv_buf[i+2] == '\r' && recv_buf[i+3] == '\n') {
                body_start = &recv_buf[i + 4];
                break;
            }
        }
        uint32_t blen = total - (uint32_t)(body_start - recv_buf);
        if (blen > max_resp - 1) blen = max_resp - 1;
        memcpy(response, body_start, blen);
        response[blen] = '\0';
        return (int)blen;
    }

    return clen;
}

int main(int argc, char **argv) {
    /* -f flag = foreground mode (for debugging) — strip it from argv first */
    int foreground = 0;
    if (argc >= 2 && strcmp(argv[1], "-f") == 0) {
        foreground = 1;
        argc--;
        for (int i = 1; i < argc; i++) argv[i] = argv[i + 1];
    }

    /* Determine host/port from argv or /etc/limnx.conf [inference] */
    char host_buf[64], port_buf[16];
    const char *host_str = NULL;
    const char *port_str = NULL;

    if (argc >= 3) {
        host_str = argv[1];
        port_str = argv[2];
    } else if (config_get("/etc/limnx.conf", "inference", "remote_host",
                          host_buf, sizeof(host_buf)) == 0 &&
               config_get("/etc/limnx.conf", "inference", "remote_port",
                          port_buf, sizeof(port_buf)) == 0) {
        host_str = host_buf;
        port_str = port_buf;
        printf("[proxy] Loaded config from /etc/limnx.conf: %s:%s\n",
               host_str, port_str);
    } else {
        printf("Usage: inferd_proxy [-f] <host_ip> <port> [svc_name] [sock_path]\n");
        printf("       Or set [inference] remote_host=, remote_port= in /etc/limnx.conf\n");
        return 1;
    }

    remote_ip   = parse_ip(host_str);
    remote_port = (uint16_t)atoi(port_str);
    const char *svc_name  = (argc >= 4) ? argv[3] : "default";
    const char *sock_path = (argc >= 5) ? argv[4] : "/tmp/inferd_proxy.sock";

    printf("[proxy] Starting: remote=%s:%s svc=%s\n",
           host_str, port_str, svc_name);

    if (!foreground) {
        /* Daemonize: fork, parent exits, child continues in background */
        long dpid = sys_fork();
        if (dpid < 0) {
            printf("[proxy] fork failed\n");
            return 1;
        }
        if (dpid > 0) {
            return 0;
        }
        sys_setsid();
        long null_fd = sys_open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            sys_dup2(null_fd, 0);
            sys_dup2(null_fd, 1);
            sys_dup2(null_fd, 2);
            sys_close(null_fd);
        }
    }

    /* Create and bind unix socket */
    long sock_fd = sys_unix_socket();
    if (sock_fd < 0) { printf("[proxy] Failed to create socket\n"); return 1; }

    if (sys_unix_bind(sock_fd, sock_path) < 0) {
        printf("[proxy] Failed to bind %s\n", sock_path);
        sys_close(sock_fd);
        return 1;
    }

    if (sys_unix_listen(sock_fd) < 0) {
        printf("[proxy] Failed to listen\n");
        sys_close(sock_fd);
        return 1;
    }

    /* Register with kernel inference service */
    long ret = sys_infer_register(svc_name, sock_path);
    if (ret < 0) {
        printf("[proxy] Failed to register service '%s'\n", svc_name);
        sys_close(sock_fd);
        return 1;
    }

    printf("[proxy] Ready — forwarding '%s' to %s:%u\n",
           svc_name, host_str, remote_port);

    sys_infer_health(0);

    /* Serve requests */
    int served = 0;
    for (;;) {
        sys_infer_health((long)served);

        long client_fd = sys_unix_accept(sock_fd);
        if (client_fd < 0) {
            sys_yield();
            continue;
        }

        /* Read prompt from local client */
        char req_buf[MAX_PROMPT];
        long n = sys_read(client_fd, req_buf, sizeof(req_buf) - 1);
        if (n > 0) {
            req_buf[n] = '\0';
            printf("[proxy] Request #%d: %ld bytes\n", served + 1, n);

            /* Forward to remote GPU server */
            char response[MAX_RESP];
            int rlen = forward_request(req_buf, (uint32_t)n,
                                       response, sizeof(response) - 1);

            if (rlen > 0) {
                response[rlen] = '\0';
                sys_fwrite(client_fd, response, rlen);
                printf("[proxy] Response: %d bytes\n", rlen);
            } else {
                const char *err = "(remote server error)";
                sys_fwrite(client_fd, err, strlen(err));
                printf("[proxy] Remote server failed\n");
            }
        }

        sys_close(client_fd);
        served++;
    }

    sys_close(sock_fd);
    return 0;
}
