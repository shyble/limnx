/*
 * init.c — Init system (pid 1)
 *
 * First userspace process. Reads /etc/inittab, spawns services,
 * reaps zombies, respawns crashed services.
 *
 * /etc/inittab format (one entry per line):
 *   name:path:flags
 *   flags: respawn, once, wait
 *   Lines starting with '#' are comments, empty lines ignored.
 *
 * Example:
 *   serviced:/serviced.elf:respawn
 *   shell:/shell.elf:wait
 */

#include "../libc/libc.h"

#define MAX_SERVICES 16
#define MAX_LINE     256

/* Service flags */
#define SVC_RESPAWN  (1 << 0)   /* auto-restart on exit */
#define SVC_WAIT     (1 << 1)   /* wait for exit before continuing */
#define SVC_ONCE     (1 << 2)   /* run once, don't respawn */

typedef struct {
    char name[32];
    char path[128];
    uint32_t flags;
    long pid;           /* current pid, 0 if not running */
    int started;        /* has been started at least once */
} service_t;

static service_t services[MAX_SERVICES];
static int service_count = 0;

/* Parse a single inittab line: name:path:flags */
static int parse_line(const char *line) {
    if (service_count >= MAX_SERVICES) return -1;
    if (line[0] == '#' || line[0] == '\0' || line[0] == '\n') return 0;

    service_t *svc = &services[service_count];
    memset(svc, 0, sizeof(*svc));

    /* Parse name */
    int i = 0, j = 0;
    while (line[i] && line[i] != ':' && j < 31)
        svc->name[j++] = line[i++];
    svc->name[j] = '\0';
    if (line[i] != ':') return -1;
    i++;

    /* Parse path */
    j = 0;
    while (line[i] && line[i] != ':' && j < 127)
        svc->path[j++] = line[i++];
    svc->path[j] = '\0';
    if (line[i] != ':') return -1;
    i++;

    /* Parse flags */
    if (strstr(&line[i], "respawn")) svc->flags |= SVC_RESPAWN;
    if (strstr(&line[i], "wait"))    svc->flags |= SVC_WAIT;
    if (strstr(&line[i], "once"))    svc->flags |= SVC_ONCE;

    /* Default to once if no flags */
    if (svc->flags == 0) svc->flags = SVC_ONCE;

    service_count++;
    return 0;
}

/* Append a service from a [services] entry in /etc/limnx.conf.
 * name is the key, path is the value (e.g. "/sbin/inferd_proxy"). */
static void add_conf_service(const char *name, const char *path) {
    if (service_count >= MAX_SERVICES) return;
    /* Skip if name already registered via inittab — inittab takes precedence */
    for (int i = 0; i < service_count; i++) {
        if (strcmp(services[i].name, name) == 0) return;
    }
    service_t *svc = &services[service_count];
    memset(svc, 0, sizeof(*svc));
    int i = 0;
    while (name[i] && i < 31) { svc->name[i] = name[i]; i++; }
    svc->name[i] = '\0';
    i = 0;
    while (path[i] && i < 127) { svc->path[i] = path[i]; i++; }
    svc->path[i] = '\0';
    svc->flags = SVC_RESPAWN;
    service_count++;
}

/* Read [services] section from /etc/limnx.conf, register each as respawn. */
static void read_limnx_conf(void) {
    char key[32], value[128];
    int state = 0;
    while (config_iter_section("/etc/limnx.conf", "services", &state,
                                key, sizeof(key), value, sizeof(value)) == 0) {
        if (key[0] && value[0])
            add_conf_service(key, value);
    }
}

/* Read and parse /etc/inittab */
static int read_inittab(void) {
    long fd = sys_open("/etc/inittab", 0);
    if (fd < 0) {
        printf("[init] /etc/inittab not found, using defaults\n");
        return -1;
    }

    char buf[2048];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Parse line by line */
    char line[MAX_LINE];
    int li = 0, bi = 0;
    while (bi <= n) {
        if (buf[bi] == '\n' || buf[bi] == '\0') {
            line[li] = '\0';
            if (li > 0) parse_line(line);
            li = 0;
            bi++;
        } else {
            if (li < MAX_LINE - 1)
                line[li++] = buf[bi];
            bi++;
        }
    }
    return 0;
}

/* Parse path into argv: split "path arg1 arg2" into argv[] */
static int parse_argv(const char *path, const char **argv, int max_args,
                      char *buf, int buf_size) {
    int argc = 0, bi = 0, pi = 0;
    while (path[pi] && argc < max_args - 1) {
        /* Skip spaces */
        while (path[pi] == ' ') pi++;
        if (!path[pi]) break;
        /* Start of arg */
        argv[argc++] = &buf[bi];
        while (path[pi] && path[pi] != ' ' && bi < buf_size - 1)
            buf[bi++] = path[pi++];
        buf[bi++] = '\0';
    }
    argv[argc] = (void *)0;
    return argc;
}

/* Spawn a service via fork + execve */
static long spawn_service(service_t *svc) {
    long pid = sys_fork();
    if (pid < 0) {
        printf("[init] fork failed for %s\n", svc->name);
        return -1;
    }
    if (pid == 0) {
        /* Child */
        int is_daemon = !(svc->flags & SVC_WAIT);

        if (is_daemon) {
            /* Detach from console PTY — prevents garbled output at boot */
            sys_setsid();
            long null_fd = sys_open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                sys_dup2(null_fd, 0);  /* stdin  → /dev/null */
                sys_dup2(null_fd, 1);  /* stdout → /dev/null */
                sys_dup2(null_fd, 2);  /* stderr → /dev/null */
                sys_close(null_fd);
            }
        }

        /* Parse path into argv (supports "path arg1 arg2") */
        const char *argv[8];
        char argv_buf[256];
        parse_argv(svc->path, argv, 8, argv_buf, sizeof(argv_buf));

        sys_execve(argv[0], argv);

        /* Fallback: if path is bare ("serviced") or refers to root .elf
         * ("/serviced.elf") that no longer exists, try /sbin/<basename>. */
        const char *orig = argv[0];
        const char *base = orig;
        for (const char *p = orig; *p; p++)
            if (*p == '/') base = p + 1;
        /* Strip .elf suffix if present */
        char name_buf[64];
        int nlen = 0;
        while (base[nlen] && nlen < 60) { name_buf[nlen] = base[nlen]; nlen++; }
        name_buf[nlen] = '\0';
        if (nlen >= 4 && name_buf[nlen-4] == '.' && name_buf[nlen-3] == 'e' &&
            name_buf[nlen-2] == 'l' && name_buf[nlen-1] == 'f') {
            name_buf[nlen-4] = '\0';
        }
        char sbin_path[80];
        sbin_path[0] = '/'; sbin_path[1] = 's'; sbin_path[2] = 'b';
        sbin_path[3] = 'i'; sbin_path[4] = 'n'; sbin_path[5] = '/';
        int sp = 6;
        for (int i = 0; name_buf[i] && sp < 78; i++) sbin_path[sp++] = name_buf[i];
        sbin_path[sp] = '\0';
        argv[0] = sbin_path;
        sys_execve(argv[0], argv);

        /* All exec attempts failed */
        sys_write("[init] exec failed: ", 20);
        sys_write(svc->path, strlen(svc->path));
        sys_write("\n", 1);
        sys_exit(127);
    }
    /* Parent */
    svc->pid = pid;
    svc->started = 1;
    printf("[init] started %s (pid %ld)\n", svc->name, pid);
    return pid;
}

/* Find service by pid */
static service_t *find_service_by_pid(long pid) {
    for (int i = 0; i < service_count; i++) {
        if (services[i].pid == pid)
            return &services[i];
    }
    return (void *)0;
}

int main(void) {
    printf("[init] Limnx init (pid %ld)\n", sys_getpid());

    /* Set up environment */
    sys_setenv("LIMNX_VERSION", "1.27");
    sys_setenv("PATH", "/sbin:/bin");

    /* Read config — /etc/inittab is authoritative, /etc/limnx.conf adds extras */
    int inittab_ok = (read_inittab() == 0);
    read_limnx_conf();
    if (!inittab_ok) {
        /* No inittab — use hardcoded defaults */
        service_t *svc;

        svc = &services[service_count++];
        memset(svc, 0, sizeof(*svc));
        strcpy(svc->name, "serviced");
        strcpy(svc->path, "/sbin/serviced");
        svc->flags = SVC_RESPAWN;

        svc = &services[service_count++];
        memset(svc, 0, sizeof(*svc));
        strcpy(svc->name, "shell");
        strcpy(svc->path, "/bin/ash");
        svc->flags = SVC_WAIT;
    }

    printf("[init] %d services configured\n", service_count);

    /* Start all services: launch daemons first, shell last */
    for (int i = 0; i < service_count; i++) {
        if (services[i].flags & SVC_WAIT) continue;  /* skip shell for now */
        spawn_service(&services[i]);
    }

    /* Small delay to let daemons detach before shell starts */
    long ts[2] = {0, 200000000};  /* 200ms */
    sys_nanosleep(ts);

    /* Now start wait-flagged services (shell) */
    for (int i = 0; i < service_count; i++) {
        if (!(services[i].flags & SVC_WAIT)) continue;

        /* Give shell its own session + foreground process group */
        spawn_service(&services[i]);
        sys_waitpid(services[i].pid);
        services[i].pid = 0;
    }

    /* Silence init's own output so it doesn't compete with shell */
    {
        long null_fd = sys_open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            sys_dup2(null_fd, 1);
            sys_dup2(null_fd, 2);
            sys_close(null_fd);
        }
    }

    /* Main loop: reap children, respawn if needed */
    for (;;) {
        /* Poll all running services with WNOHANG */
        int any_running = 0;
        for (int i = 0; i < service_count; i++) {
            if (services[i].pid <= 0) continue;
            any_running = 1;

            /* WNOHANG returns 0 for both "not exited" and "exited with status 0".
             * Use /proc/<pid> to disambiguate: if gone, child was reaped. */
            long status = sys_waitpid_flags(services[i].pid, WNOHANG);
            if (status == 0) {
                /* Check if process still exists via /proc */
                char ppath[32];
                int pp = 0;
                const char *pfx = "/proc/";
                while (*pfx) ppath[pp++] = *pfx++;
                long ptmp = services[i].pid;
                char rev[24]; int rp = 0;
                if (ptmp == 0) rev[rp++] = '0';
                else while (ptmp > 0) { rev[rp++] = '0' + (ptmp % 10); ptmp /= 10; }
                while (rp > 0) ppath[pp++] = rev[--rp];
                ppath[pp] = '\0';
                long pfd = sys_open(ppath, 0);
                if (pfd >= 0) {
                    sys_close(pfd);
                    continue;  /* Still running */
                }
                /* Process gone — was reaped with status 0 */
            }
            if (status == -1) {
                /* Process not found — already reaped elsewhere */
                services[i].pid = 0;
                continue;
            }

            /* Child exited */
            printf("[init] %s (pid %ld) exited with status %ld\n",
                   services[i].name, services[i].pid, status);
            services[i].pid = 0;

            /* Respawn if configured */
            if (services[i].flags & SVC_RESPAWN) {
                printf("[init] respawning %s\n", services[i].name);
                spawn_service(&services[i]);
            }
        }

        if (!any_running) break;  /* All services done */

        /* Brief sleep to avoid busy-waiting */
        long ts[2] = {0, 100000000};  /* 100ms */
        sys_nanosleep(ts);
    }

    return 0;
}
