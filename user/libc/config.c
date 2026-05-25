/* Minimal INI parser for /etc/limnx.conf and similar config files.
 *
 * Format:
 *   # comment line
 *   [section]
 *   key = value
 *   key=value
 *
 * Whitespace around '=' is stripped. Leading/trailing whitespace on values
 * is stripped. Comments and blank lines are ignored. Section names and keys
 * are case-sensitive.
 */
#include "libc.h"

#define CONFIG_BUF_MAX 4096

static int is_ws(char c) { return c == ' ' || c == '\t'; }

/* Read file into buf, return bytes read (0 if empty / not found). */
static long read_file(const char *path, char *buf, long max) {
    long fd = sys_open(path, O_RDONLY);
    if (fd < 0) return 0;
    long total = 0;
    while (total < max - 1) {
        long n = sys_read(fd, buf + total, max - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    sys_close(fd);
    buf[total] = '\0';
    return total;
}

/* config_get: look up [section] key in the given file.
 * Returns 0 on success, -1 on not found. Value is copied into out (NUL-terminated). */
int config_get(const char *path, const char *section, const char *key,
               char *out, int out_size) {
    static char buf[CONFIG_BUF_MAX];
    long n = read_file(path, buf, sizeof(buf));
    if (n <= 0) return -1;

    int in_section = (section == NULL || section[0] == '\0');
    int i = 0;
    while (i < n) {
        /* Skip leading whitespace */
        while (i < n && is_ws(buf[i])) i++;

        /* Section header */
        if (i < n && buf[i] == '[') {
            i++;
            int sstart = i;
            while (i < n && buf[i] != ']' && buf[i] != '\n') i++;
            int slen = i - sstart;
            if (i < n && buf[i] == ']') i++;
            /* Match section */
            if (section) {
                int klen = 0;
                while (section[klen]) klen++;
                in_section = (slen == klen);
                if (in_section) {
                    for (int j = 0; j < klen; j++) {
                        if (buf[sstart + j] != section[j]) { in_section = 0; break; }
                    }
                }
            }
            /* Skip to end of line */
            while (i < n && buf[i] != '\n') i++;
            if (i < n) i++;
            continue;
        }

        /* Skip comments and blank lines */
        if (i < n && (buf[i] == '#' || buf[i] == ';' || buf[i] == '\n')) {
            while (i < n && buf[i] != '\n') i++;
            if (i < n) i++;
            continue;
        }

        if (i >= n) break;

        /* Parse key=value */
        int kstart = i;
        while (i < n && buf[i] != '=' && buf[i] != '\n') i++;
        int kend = i;
        /* Strip trailing whitespace from key */
        while (kend > kstart && is_ws(buf[kend - 1])) kend--;

        if (i < n && buf[i] == '=') {
            i++;
            while (i < n && is_ws(buf[i])) i++;
            int vstart = i;
            while (i < n && buf[i] != '\n' && buf[i] != '#') i++;
            int vend = i;
            while (vend > vstart && is_ws(buf[vend - 1])) vend--;

            /* Match key only if we're in the right section */
            if (in_section) {
                int klen = 0;
                while (key[klen]) klen++;
                int match = ((kend - kstart) == klen);
                if (match) {
                    for (int j = 0; j < klen; j++) {
                        if (buf[kstart + j] != key[j]) { match = 0; break; }
                    }
                }
                if (match) {
                    int vlen = vend - vstart;
                    if (vlen >= out_size) vlen = out_size - 1;
                    for (int j = 0; j < vlen; j++) out[j] = buf[vstart + j];
                    out[vlen] = '\0';
                    return 0;
                }
            }
        }

        /* Skip to next line */
        while (i < n && buf[i] != '\n') i++;
        if (i < n) i++;
    }
    return -1;
}

/* config_get_int: convenience wrapper, returns parsed integer or default. */
long config_get_int(const char *path, const char *section, const char *key,
                    long default_val) {
    char buf[32];
    if (config_get(path, section, key, buf, sizeof(buf)) < 0)
        return default_val;
    return atol(buf);
}

/* config_iter_section: iterate all key=value pairs in a section.
 * Pass *state = 0 on first call, function updates it. Returns 0 on each
 * pair (key/value populated), -1 when done. */
int config_iter_section(const char *path, const char *section, int *state,
                        char *key, int key_size, char *value, int value_size) {
    static char buf[CONFIG_BUF_MAX];
    static long buflen = 0;
    static const char *cached_path = NULL;

    /* Cache the file content on first call (state==0) */
    if (*state == 0 || cached_path != path) {
        buflen = read_file(path, buf, sizeof(buf));
        cached_path = path;
        *state = 1;
    }
    if (buflen <= 0) return -1;

    int i = *state - 1;
    if (i < 0) i = 0;
    int in_section = (section == NULL || section[0] == '\0');

    /* Re-scan to find which section we're in at offset i */
    if (i > 0) {
        int j = 0;
        while (j < i) {
            while (j < buflen && is_ws(buf[j])) j++;
            if (j < buflen && buf[j] == '[') {
                j++;
                int sstart = j;
                while (j < buflen && buf[j] != ']' && buf[j] != '\n') j++;
                int slen = j - sstart;
                if (section) {
                    int klen = 0;
                    while (section[klen]) klen++;
                    in_section = (slen == klen);
                    if (in_section) {
                        for (int k = 0; k < klen; k++) {
                            if (buf[sstart + k] != section[k]) { in_section = 0; break; }
                        }
                    }
                }
            }
            while (j < buflen && buf[j] != '\n') j++;
            if (j < buflen) j++;
        }
    }

    while (i < buflen) {
        while (i < buflen && is_ws(buf[i])) i++;

        if (i < buflen && buf[i] == '[') {
            i++;
            int sstart = i;
            while (i < buflen && buf[i] != ']' && buf[i] != '\n') i++;
            int slen = i - sstart;
            if (i < buflen && buf[i] == ']') i++;
            if (section) {
                int klen = 0;
                while (section[klen]) klen++;
                in_section = (slen == klen);
                if (in_section) {
                    for (int j = 0; j < klen; j++) {
                        if (buf[sstart + j] != section[j]) { in_section = 0; break; }
                    }
                }
            }
            while (i < buflen && buf[i] != '\n') i++;
            if (i < buflen) i++;
            continue;
        }

        if (i < buflen && (buf[i] == '#' || buf[i] == ';' || buf[i] == '\n')) {
            while (i < buflen && buf[i] != '\n') i++;
            if (i < buflen) i++;
            continue;
        }

        if (i >= buflen) break;

        int kstart = i;
        while (i < buflen && buf[i] != '=' && buf[i] != '\n') i++;
        int kend = i;
        while (kend > kstart && is_ws(buf[kend - 1])) kend--;

        if (i < buflen && buf[i] == '=') {
            i++;
            while (i < buflen && is_ws(buf[i])) i++;
            int vstart = i;
            while (i < buflen && buf[i] != '\n' && buf[i] != '#') i++;
            int vend = i;
            while (vend > vstart && is_ws(buf[vend - 1])) vend--;
            /* Skip to next line for next iteration */
            while (i < buflen && buf[i] != '\n') i++;
            if (i < buflen) i++;

            if (in_section) {
                int klen = kend - kstart;
                if (klen >= key_size) klen = key_size - 1;
                for (int j = 0; j < klen; j++) key[j] = buf[kstart + j];
                key[klen] = '\0';

                int vlen = vend - vstart;
                if (vlen >= value_size) vlen = value_size - 1;
                for (int j = 0; j < vlen; j++) value[j] = buf[vstart + j];
                value[vlen] = '\0';

                *state = i + 1;
                return 0;
            }
            continue;
        }

        while (i < buflen && buf[i] != '\n') i++;
        if (i < buflen) i++;
    }
    return -1;
}
