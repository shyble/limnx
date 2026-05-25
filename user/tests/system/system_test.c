/*
 * system_test.c — System-level integration tests
 * Tests: init, /sbin layout, busybox /bin layout, /etc configs, env
 * Portable — no arch-specific code.
 */
#include "../limntest.h"

static int file_exists(const char *path) {
    long fd = sys_open(path, 0);
    if (fd < 0) return 0;
    sys_close(fd);
    return 1;
}

static void test_init(void) {
    lt_ok(file_exists("/etc/inittab"), "/etc/inittab exists");
    lt_ok(file_exists("/proc/1/status"), "init (pid 1) /proc status");
    lt_ok(file_exists("/proc/1/stat"), "init (pid 1) /proc stat (busybox ps)");
    lt_ok(file_exists("/proc/1/cmdline"), "init (pid 1) /proc cmdline");
}

static void test_env(void) {
    char val[64];
    long ret = sys_getenv("LIMNX_VERSION", val, 64);
    lt_ok(ret >= 0, "LIMNX_VERSION env set");
    if (ret >= 0)
        lt_ok(val[0] != '\0', "LIMNX_VERSION is non-empty");
    else
        lt_ok(0, "LIMNX_VERSION is non-empty");

    ret = sys_getenv("PATH", val, 64);
    lt_ok(ret >= 0, "PATH env set");
    if (ret >= 0)
        lt_ok(strstr(val, "/sbin") != NULL || strstr(val, "/bin") != NULL,
              "PATH contains /sbin or /bin");
    else
        lt_ok(0, "PATH contains /sbin or /bin");
}

static void test_sbin_symlinks(void) {
    /* /sbin/ should contain symlinks to Limnx daemons */
    const char *sbin_tools[] = {
        "/sbin/init", "/sbin/serviced", "/sbin/agentd", "/sbin/inferd",
        "/sbin/inferd_proxy", "/sbin/shell", "/sbin/login",
        NULL
    };
    int all = 1;
    for (int i = 0; sbin_tools[i]; i++) {
        if (!file_exists(sbin_tools[i])) all = 0;
    }
    lt_ok(all, "/sbin/ symlinks resolve");
}

static void test_bin_busybox(void) {
    /* /bin/ should contain busybox applet symlinks */
    const char *bin_apps[] = {
        "/bin/ash", "/bin/ls", "/bin/cat", "/bin/echo", "/bin/grep",
        "/bin/ps", "/bin/wc", "/bin/cp", "/bin/mv", "/bin/rm",
        NULL
    };
    int all = 1;
    for (int i = 0; bin_apps[i]; i++) {
        if (!file_exists(bin_apps[i])) all = 0;
    }
    lt_ok(all, "/bin/ busybox applets resolve");
}

static void test_no_redundant_coreutils(void) {
    /* These C coreutils were removed in Stage 1.27 — busybox provides them
     * via /bin/. The ASM demo cat.elf (user/asm/cat.asm) stays as legacy
     * educational code and is intentionally NOT listed here. */
    const char *gone[] = {
        "/echo.elf", "/ls.elf", "/cp.elf", "/mv.elf", "/rm.elf",
        "/ps.elf", "/grep.elf", "/head.elf", "/tail.elf", "/wc.elf",
        "/env.elf", "/whoami.elf", "/killcmd.elf", "/mkdircmd.elf",
        "/chmodcmd.elf", "/chowncmd.elf", "/mountcmd.elf", "/umount.elf",
        NULL
    };
    int any_present = 0;
    for (int i = 0; gone[i]; i++) {
        if (file_exists(gone[i])) any_present = 1;
    }
    lt_ok(!any_present, "redundant C coreutils removed (busybox wins)");
}

static void test_limnx_conf(void) {
    lt_ok(file_exists("/etc/limnx.conf"), "/etc/limnx.conf exists");
    /* Parse [inference] backend value */
    char val[64];
    int ret = config_get("/etc/limnx.conf", "inference", "backend", val, sizeof(val));
    lt_ok(ret == 0, "config_get [inference] backend");
    if (ret == 0)
        lt_ok(val[0] != '\0', "[inference] backend has value");
    else
        lt_ok(0, "[inference] backend has value");
}

static void test_bin_exec(void) {
    /* Busybox echo via /bin/ash -c 'echo' would need a shell parser;
     * just verify direct exec of /bin/echo (symlink to busybox) runs. */
    long child = sys_fork();
    if (child == 0) {
        const char *argv[] = {"echo", "ok", NULL};
        sys_execve("/bin/echo", argv);
        sys_exit(127);
    }
    long st = sys_waitpid(child);
    lt_ok(st == 0, "/bin/echo executes");
}

static void test_exit_status(void) {
    long child = sys_fork();
    if (child == 0) sys_exit(42);
    long st = sys_waitpid(child);
    lt_ok(st == 42, "exit status propagation");

    child = sys_fork();
    if (child == 0) sys_exit(0);
    st = sys_waitpid(child);
    lt_ok(st == 0, "exit status 0 propagation");
}

static void test_env_setget(void) {
    sys_setenv("TEST_KEY", "test_value");
    char val[64];
    long ret = sys_getenv("TEST_KEY", val, 64);
    lt_ok(ret >= 0 && strcmp(val, "test_value") == 0,
          "setenv+getenv roundtrip");
}

int main(void) {
    lt_suite("system");
    test_init();
    test_env();
    test_sbin_symlinks();
    test_bin_busybox();
    test_no_redundant_coreutils();
    test_limnx_conf();
    test_bin_exec();
    test_exit_status();
    test_env_setget();
    return lt_done();
}
