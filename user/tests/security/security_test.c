/*
 * security_test.c — Permission and security tests
 * Tests: uid/gid, capabilities, umask
 * Portable — no arch-specific code.
 */
#include "../limntest.h"
#include "limnx/syscall_nr.h"

static void test_uid_gid(void) {
    long uid = sys_getuid();
    long gid = sys_getgid();
    lt_ok(uid >= 0, "getuid returns value");
    lt_ok(gid >= 0, "getgid returns value");
    long euid = sys_geteuid();
    long egid = sys_getegid();
    lt_ok(euid >= 0, "geteuid returns value");
    lt_ok(egid >= 0, "getegid returns value");
}

static void test_passwd(void) {
    long fd = sys_open("/etc/passwd", 0);
    lt_ok(fd >= 0, "/etc/passwd exists");
    if (fd >= 0) {
        char buf[256];
        long n = sys_read(fd, buf, 255);
        if (n > 0) buf[n] = '\0';
        lt_ok(lt_strcontains(buf, "root"), "passwd contains root");
        sys_close(fd);
    } else {
        lt_ok(0, "passwd contains root");
    }
}

static void test_umask(void) {
    long old = sys_umask(0077);
    lt_ok(old >= 0, "umask returns old value");
    sys_umask(old);  /* restore */
}

static void test_chmod_chown(void) {
    sys_open("/sec_test_file.txt", O_CREAT | O_RDWR);
    long ret = sys_chmod("/sec_test_file.txt", 0755);
    lt_ok(ret == 0, "chmod succeeds");
    ret = sys_chown("/sec_test_file.txt", 0, 0);
    lt_ok(ret == 0, "chown succeeds");
}

static void test_capabilities(void) {
    long caps = sys_getcap();
    lt_ok(caps != 0, "process has capabilities");
}

static void test_setuid_setgid(void) {
    /* We're running as root — verify we can set uid/gid */
    long ret = sys_setuid(0);
    lt_ok(ret == 0, "setuid(0) succeeds as root");
    ret = sys_setgid(0);
    lt_ok(ret == 0, "setgid(0) succeeds as root");
}

/* Filter allowing every standard syscall except fork. */
static void filter_all_but_fork(unsigned long bits[SECCOMP_FILTER_WORDS]) {
    for (int i = 0; i < SECCOMP_FILTER_WORDS; i++)
        bits[i] = ~0UL;
    bits[SYS_FORK / 64] &= ~(1UL << (SYS_FORK % 64));
}

/* Exit 42 if fork is denied with EACCES, 99 otherwise. */
static void seccomp_fork_probe(void) {
    long ret = sys_fork();
    if (ret == 0)
        sys_exit(0);
    sys_exit(ret == -13 /* EACCES */ ? 42 : 99);
}

static void test_seccomp(void) {
    /* Fork a child, apply seccomp, try a blocked syscall */
    long pid = sys_fork();
    if (pid == 0) {
        unsigned long bits[SECCOMP_FILTER_WORDS] = {0};
        SECCOMP_ALLOW(bits, SYS_READ);
        SECCOMP_ALLOW(bits, SYS_WRITE);
        SECCOMP_ALLOW(bits, SYS_SCHED_YIELD);
        SECCOMP_ALLOW(bits, SYS_GETPID);
        SECCOMP_ALLOW(bits, SYS_EXIT);
        SECCOMP_ALLOW(bits, SYS_EXIT_GROUP);
        SECCOMP_ALLOW(bits, SYS_SECCOMP);
        sys_seccomp_filter(bits, 0 /* not strict — return EACCES */);

        /* getpid should work (allowed) */
        if (sys_getpid() > 0)
            seccomp_fork_probe();
        sys_exit(99);
    }

    lt_ok(pid > 0, "seccomp test fork");
    if (pid > 0) {
        long status = sys_waitpid(pid);
        lt_ok(status == 42, "seccomp blocks fork (child exit=42)");
    }
}

static void test_seccomp_strict(void) {
    /* Strict mode: blocked syscall → process killed immediately */
    long pid = sys_fork();
    if (pid == 0) {
        unsigned long bits[SECCOMP_FILTER_WORDS] = {0};
        SECCOMP_ALLOW(bits, SYS_WRITE);
        SECCOMP_ALLOW(bits, SYS_EXIT);
        SECCOMP_ALLOW(bits, SYS_EXIT_GROUP);
        sys_seccomp_filter(bits, 1 /* strict */);

        /* Try getpid — not in allowlist, strict → killed */
        sys_getpid();
        /* Should never reach here — write a marker to prove */
        sys_write("ALIVE", 5);
        sys_exit(99);
    }

    lt_ok(pid > 0, "seccomp strict fork");
    if (pid > 0) {
        long status = sys_waitpid(pid);
        /* Child killed → status should NOT be 99 (normal exit) */
        lt_ok(status != 99 && status != 0, "seccomp strict kills on blocked syscall");
    }
}

static void test_seccomp_cannot_widen(void) {
    /* A filtered process must not be able to clear or widen its filter,
     * neither via the legacy mask form nor with an all-zero mask. */
    long pid = sys_fork();
    if (pid == 0) {
        unsigned long bits[SECCOMP_FILTER_WORDS];
        filter_all_but_fork(bits);
        sys_seccomp_filter(bits, 0);

        sys_seccomp(0, 0, 0);
        sys_seccomp(~0UL, 0, ~0UL);
        unsigned long all[SECCOMP_FILTER_WORDS];
        for (int i = 0; i < SECCOMP_FILTER_WORDS; i++)
            all[i] = ~0UL;
        sys_seccomp_filter(all, 0);

        seccomp_fork_probe();
    }

    lt_ok(pid > 0, "seccomp widen test fork");
    if (pid > 0)
        lt_ok(sys_waitpid(pid) == 42, "seccomp filter cannot be cleared or widened");
}

static void test_seccomp_survives_exec(void) {
    long pid = sys_fork();
    if (pid == 0) {
        unsigned long bits[SECCOMP_FILTER_WORDS];
        filter_all_but_fork(bits);
        sys_seccomp_filter(bits, 0);

        const char *argv[] = {"/security_test.elf", "--seccomp-probe", (void *)0};
        sys_execve("/security_test.elf", argv);
        sys_exit(98);  /* exec failed */
    }

    lt_ok(pid > 0, "seccomp exec test fork");
    if (pid > 0)
        lt_ok(sys_waitpid(pid) == 42, "seccomp filter survives execve");
}

static void test_seccomp_spawn_inherits(void) {
    /* Spawning a new process from a path must not escape the filter */
    long pid = sys_fork();
    if (pid == 0) {
        unsigned long bits[SECCOMP_FILTER_WORDS];
        filter_all_but_fork(bits);
        sys_seccomp_filter(bits, 0);

        const char *argv[] = {"/security_test.elf", "--seccomp-probe", (void *)0};
        long child = sys_exec("/security_test.elf", argv);
        if (child <= 0)
            sys_exit(98);
        sys_exit(sys_waitpid(child));
    }

    lt_ok(pid > 0, "seccomp spawn test fork");
    if (pid > 0)
        lt_ok(sys_waitpid(pid) == 42, "seccomp filter inherited by spawned process");
}

#define SEC_DIR "/tmp/sectest"

static void write_file(const char *path, const char *data, long len) {
    long fd = sys_create(path);
    if (fd >= 0) {
        sys_fwrite(fd, data, len);
        sys_close(fd);
    }
}

static int file_has(const char *path, const char *want) {
    char buf[16];
    long fd = sys_open(path, 0);
    if (fd < 0) return 0;
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n < 0) return 0;
    buf[n] = '\0';
    return lt_strcontains(buf, want) && n == (long)strlen(want);
}

/* Root-owned test tree: 0755 dirs, 0644 files. */
static void setup_sec_dir(void) {
    sys_mkdir(SEC_DIR);
    sys_chmod(SEC_DIR, 0755);
    sys_mkdir(SEC_DIR "/sub");
    sys_chmod(SEC_DIR "/sub", 0755);
    write_file(SEC_DIR "/victim", "keep", 4);
    sys_chmod(SEC_DIR "/victim", 0644);
    write_file(SEC_DIR "/sub/file", "data", 4);
    sys_chmod(SEC_DIR "/sub/file", 0644);
    write_file(SEC_DIR "/subx", "data", 4);
    sys_chmod(SEC_DIR "/subx", 0644);
}

static void test_dac_as_user(void) {
    /* An ordinary user must not modify root's files, whatever syscall */
    long pid = sys_fork();
    if (pid == 0) {
        if (sys_setuid(65534) != 0) sys_exit(0);
        int ok = 0;
        if (sys_truncate(SEC_DIR "/victim", 0) == -13) ok |= 1;
        if (sys_rename(SEC_DIR "/victim", SEC_DIR "/moved") == -13) ok |= 2;
        if (sys_access(SEC_DIR "/victim", 2 /* W_OK */) == -13) ok |= 4;
        if (sys_access(SEC_DIR "/victim", 4 /* R_OK */) == 0) ok |= 8;
        sys_exit(ok);
    }
    long st = pid > 0 ? sys_waitpid(pid) : 0;
    lt_ok(st & 1, "user cannot truncate root's file");
    lt_ok(st & 2, "user cannot rename in root's directory");
    lt_ok(st & 4, "access(W_OK) denied on root's 0644 file");
    lt_ok(st & 8, "access(R_OK) allowed on root's 0644 file");
    lt_ok(file_has(SEC_DIR "/victim", "keep"), "root's file left intact");
}

static void test_exec_perm_bits(void) {
    /* Exec must honour the owner/group/other x bits, not only "other".
     * Uses the root-owned /hello.elf, restoring its mode afterwards. */
    const char *path = "/hello.elf";
    const char *argv[] = {path, (void *)0};

    sys_chmod(path, 0700);
    long pid = sys_fork();
    if (pid == 0) {
        sys_execve(path, argv);
        sys_exit(98);
    }
    lt_ok(pid > 0 && sys_waitpid(pid) == 0, "owner can exec 0700 file");

    pid = sys_fork();
    if (pid == 0) {
        sys_setuid(65534);
        sys_execve(path, argv);
        sys_exit(98);
    }
    lt_ok(pid > 0 && sys_waitpid(pid) == 98, "other user cannot exec 0700 file");

    sys_chmod(path, 0644);
    pid = sys_fork();
    if (pid == 0) {
        sys_execve(path, argv);
        sys_exit(98);
    }
    lt_ok(pid > 0 && sys_waitpid(pid) == 98, "root cannot exec file without x bits");

    sys_chmod(path, 0755);
}

static void test_kill_perm(void) {
    /* A root process in its own process group */
    long victim = sys_fork();
    if (victim == 0) {
        sys_setpgid(0, 0);
        long ts[2] = {0, 50000000};
        for (int i = 0; i < 200; i++)
            sys_nanosleep(ts);
        sys_exit(0);
    }
    if (victim > 0)
        sys_setpgid(victim, victim);

    long pid = sys_fork();
    if (pid == 0) {
        if (sys_setuid(65534) != 0) sys_exit(0);
        int ok = 0;
        if (sys_kill(-victim, SIGKILL) == -1 /* EPERM */) ok |= 1;
        if (sys_kill(victim, SIGKILL) == -1 /* EPERM */) ok |= 2;
        sys_exit(ok);
    }
    long st = pid > 0 ? sys_waitpid(pid) : 0;
    lt_ok(st & 1, "user cannot signal root's process group");
    lt_ok(st & 2, "user cannot signal root's process");

    if (victim > 0) {
        sys_kill(victim, SIGKILL);
        sys_waitpid(victim);
    }
}

static void test_token_paths(void) {
    /* A token scoped to SEC_DIR/sub must not reach outside it via ".."
     * or a sibling whose name merely starts with "sub". */
    long pid = sys_fork();
    if (pid == 0) {
        int ok = 0;
        if (sys_token_create(CAP_FS_WRITE, sys_getpid(), SEC_DIR "/sub") > 0) ok |= 1;
        sys_setcap(0, sys_getcap() & ~CAP_FS_WRITE);
        if (sys_truncate(SEC_DIR "/sub/file", 4) == 0) ok |= 2;
        if (sys_truncate(SEC_DIR "/sub/../victim", 4) == -13) ok |= 4;
        if (sys_truncate(SEC_DIR "/subx", 4) == -13) ok |= 8;
        sys_exit(ok);
    }
    long st = pid > 0 ? sys_waitpid(pid) : 0;
    lt_ok(st & 1, "token created for directory");
    lt_ok(st & 2, "token grants access inside its directory");
    lt_ok(st & 4, "token does not grant access via ..");
    lt_ok(st & 8, "token does not grant access to sibling prefix");
}

int main(int argc, char **argv) {
    if (argc > 1 && lt_strcontains(argv[1], "--seccomp-probe"))
        seccomp_fork_probe();

    lt_suite("security");
    test_uid_gid();
    test_passwd();
    test_umask();
    test_chmod_chown();
    test_capabilities();
    test_setuid_setgid();
    test_seccomp();
    test_seccomp_strict();
    test_seccomp_cannot_widen();
    test_seccomp_survives_exec();
    test_seccomp_spawn_inherits();
    setup_sec_dir();
    test_dac_as_user();
    test_exec_perm_bits();
    test_kill_perm();
    test_token_paths();
    return lt_done();
}
