/*
 * login — user login program
 *
 * Reads username, looks up in /etc/passwd, sets uid/gid, execs shell.
 * /etc/passwd format: username:x:uid:gid:gecos:home:shell
 * (password field 'x' is ignored for now)
 */

#include "../libc/libc.h"

#define PASSWD_PATH "/etc/passwd"
#define MAX_LINE 256

/* Parse a passwd line: user:x:uid:gid:gecos:home:shell */
static int parse_passwd(const char *line, char *user, int *uid, int *gid,
                        char *home, char *shell_path) {
    int field = 0, pos = 0;
    char fields[7][128];
    for (int f = 0; f < 7; f++) fields[f][0] = '\0';

    for (int i = 0; line[i] && line[i] != '\n'; i++) {
        if (line[i] == ':') {
            fields[field][pos] = '\0';
            field++;
            pos = 0;
            if (field >= 7) break;
        } else {
            if (pos < 127) fields[field][pos++] = line[i];
        }
    }
    fields[field][pos] = '\0';

    if (field < 6) return -1;

    strcpy(user, fields[0]);
    *uid = atoi(fields[2]);
    *gid = atoi(fields[3]);
    strcpy(home, fields[5]);
    strcpy(shell_path, fields[6]);
    return 0;
}

/* Look up username in /etc/passwd */
static int lookup_user(const char *username, int *uid, int *gid,
                       char *home, char *shell_path) {
    long fd = sys_open(PASSWD_PATH, 0);
    if (fd < 0) return -1;

    char buf[2048];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Parse line by line */
    char *lstart = buf;
    for (long i = 0; i <= n; i++) {
        if (buf[i] == '\n' || buf[i] == '\0') {
            buf[i] = '\0';
            if (lstart[0] != '#' && lstart[0] != '\0') {
                char user[64];
                int u, g;
                char h[128], s[128];
                if (parse_passwd(lstart, user, &u, &g, h, s) == 0) {
                    if (strcmp(user, username) == 0) {
                        *uid = u;
                        *gid = g;
                        strcpy(home, h);
                        strcpy(shell_path, s);
                        return 0;
                    }
                }
            }
            lstart = &buf[i + 1];
        }
    }
    return -1;
}

int main(void) {
    for (;;) {
        printf("\nlimnx login: ");
        char username[64];
        int pos = 0;

        /* Read username character by character */
        while (pos < 63) {
            char ch;
            long n = sys_read(0, &ch, 1);
            if (n <= 0) continue;
            if (ch == '\n' || ch == '\r') break;
            if (ch == 127 || ch == '\b') {
                if (pos > 0) { pos--; sys_write("\b \b", 3); }
                continue;
            }
            username[pos++] = ch;
            sys_write(&ch, 1);
        }
        username[pos] = '\0';

        if (pos == 0) continue;

        /* Look up user */
        int uid, gid;
        char home[128], shell_path[128];
        if (lookup_user(username, &uid, &gid, home, shell_path) < 0) {
            printf("\nLogin incorrect\n");
            continue;
        }

        /* Drop privileges: groups first, uid last, since after setuid we
         * can no longer change groups. Never start a shell half-dropped. */
        if (sys_setgroups(0, (void *)0) != 0 || sys_setgid(gid) != 0 ||
            sys_setuid(uid) != 0) {
            printf("\nlogin: failed to drop privileges\n");
            sys_exit(1);
        }

        /* Set HOME and USER env */
        sys_setenv("HOME", home);
        sys_setenv("USER", username);

        /* Change to home directory */
        sys_chdir(home);

        printf("\nWelcome, %s\n", username);

        /* Exec shell */
        const char *argv[] = {shell_path, (void *)0};
        sys_execve(shell_path, argv);

        /* If exec fails, fall back */
        printf("login: failed to exec %s\n", shell_path);
    }
    return 0;
}
