/*
 * libc_test.c — libc primitives tests
 * Tests: malloc, printf formatting, string, math
 * Portable — no arch-specific code.
 */
#include "../limntest.h"

static void test_malloc_free(void) {
    void *p = malloc(128);
    lt_ok(p != (void *)0, "malloc(128)");
    if (p) {
        memset(p, 0x55, 128);
        lt_ok(((unsigned char *)p)[0] == 0x55, "malloc writable");
        free(p);
    } else {
        lt_ok(0, "malloc writable");
    }

    /* Allocate and free many small blocks */
    int ok = 1;
    for (int i = 0; i < 50; i++) {
        void *q = malloc(32);
        if (!q) { ok = 0; break; }
        free(q);
    }
    lt_ok(ok, "malloc+free 50 cycles");
}

static void test_string_functions(void) {
    lt_ok(strlen("") == 0, "strlen empty");
    lt_ok(strlen("abcde") == 5, "strlen 5");

    char buf[64];
    strcpy(buf, "test");
    lt_ok(strcmp(buf, "test") == 0, "strcpy+strcmp");

    memset(buf, 0, 64);
    memcpy(buf, "hello", 5);
    lt_ok(buf[0] == 'h' && buf[4] == 'o', "memcpy");

    lt_ok(strncmp("abc", "abd", 2) == 0, "strncmp match");
    lt_ok(strncmp("abc", "abd", 3) != 0, "strncmp differ");
}

static void test_math(void) {
    float pi_approx = 3.14159f;
    lt_ok(sinf(0.0f) < 0.01f && sinf(0.0f) > -0.01f, "sinf(0) ≈ 0");
    lt_ok(cosf(0.0f) > 0.99f && cosf(0.0f) < 1.01f, "cosf(0) ≈ 1");
    lt_ok(sqrtf(9.0f) > 2.99f && sqrtf(9.0f) < 3.01f, "sqrtf(9) ≈ 3");
    lt_ok(expf(1.0f) > 2.71f && expf(1.0f) < 2.72f, "expf(1) ≈ e");
    lt_ok(logf(expf(1.0f)) > 0.99f && logf(expf(1.0f)) < 1.01f, "logf(e) ≈ 1");
    (void)pi_approx;
}

static void test_atoi(void) {
    lt_ok(atoi("123") == 123, "atoi positive");
    lt_ok(atoi("-42") == -42, "atoi negative");
    lt_ok(atoi("0") == 0, "atoi zero");
    lt_ok(strtoul("100", (void *)0, 10) == 100, "strtoul decimal");
    lt_ok(strtoul("ff", (void *)0, 16) == 255, "strtoul hex");
}

static void test_config_parser(void) {
    /* Write a sample config file */
    const char *path = "/tmp/test_config.ini";
    long fd = sys_create(path);
    if (fd < 0) { lt_ok(0, "config: create test file"); return; }
    const char *content =
        "# Sample config\n"
        "[inference]\n"
        "backend = remote\n"
        "remote_host = 10.0.2.2\n"
        "remote_port = 9200\n"
        "\n"
        "[services]\n"
        "inferd_proxy = /sbin/inferd_proxy\n"
        "extra = /sbin/extra arg1 arg2\n";
    int len = 0;
    while (content[len]) len++;
    sys_fwrite(fd, content, len);
    sys_close(fd);

    char buf[64];
    lt_ok(config_get(path, "inference", "backend", buf, sizeof(buf)) == 0 &&
          strcmp(buf, "remote") == 0,
          "config_get [inference] backend == remote");
    lt_ok(config_get(path, "inference", "remote_host", buf, sizeof(buf)) == 0 &&
          strcmp(buf, "10.0.2.2") == 0,
          "config_get [inference] remote_host");
    lt_ok(config_get_int(path, "inference", "remote_port", -1) == 9200,
          "config_get_int [inference] remote_port == 9200");
    lt_ok(config_get(path, "missing", "backend", buf, sizeof(buf)) < 0,
          "config_get unknown section returns -1");
    lt_ok(config_get(path, "inference", "missing_key", buf, sizeof(buf)) < 0,
          "config_get unknown key returns -1");

    /* Iterate [services] */
    char key[32], value[128];
    int state = 0;
    int count = 0;
    while (config_iter_section(path, "services", &state, key, sizeof(key),
                                value, sizeof(value)) == 0) {
        count++;
    }
    lt_ok(count == 2, "config_iter_section [services] returns 2 entries");

    sys_unlink(path);
}

int main(void) {
    lt_suite("libc");
    test_malloc_free();
    test_string_functions();
    test_math();
    test_atoi();
    test_config_parser();
    return lt_done();
}
