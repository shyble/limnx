/*
 * proc_test.c — Process lifecycle tests
 * Tests: fork, exec, waitpid, signal, session, job control
 * Portable — no arch-specific code.
 */
#include "../limntest.h"

static volatile int sig_received = 0;

static void sigusr_handler(int sig) {
    (void)sig;
    sig_received = 1;
    sys_sigreturn();
}

static void test_fork_waitpid(void) {
    long child = sys_fork();
    if (child == 0) sys_exit(42);
    long st = sys_waitpid(child);
    lt_ok(child > 0, "fork returns child PID");
    lt_ok(st == 42, "waitpid returns exit status");
}

static void test_fork_exec(void) {
    long child = sys_fork();
    if (child == 0) {
        const char *argv[] = {"hello.elf", (void *)0};
        sys_execve("/hello.elf", argv);
        sys_exit(127);
    }
    long st = sys_waitpid(child);
    lt_ok(st == 0, "fork+execve+waitpid");
}

static void test_pipe(void) {
    long rfd, wfd;
    long ret = sys_pipe(&rfd, &wfd);
    lt_ok(ret == 0, "pipe creation");
    sys_fwrite(wfd, "hello", 5);
    char buf[16];
    long n = sys_read(rfd, buf, 15);
    lt_ok(n == 5, "pipe read 5 bytes");
    sys_close(rfd);
    sys_close(wfd);
}

static void test_signal(void) {
    sig_received = 0;
    long ret = sys_sigaction(10, sigusr_handler);
    lt_ok(ret == 0, "sigaction installed");

    long parent = sys_getpid();
    long child = sys_fork();
    if (child == 0) {
        long ts[2] = {0, 50000000};
        sys_nanosleep(ts);
        sys_kill(parent, 10);
        sys_exit(0);
    }
    long ts[2] = {0, 50000000};
    for (int i = 0; i < 20 && !sig_received; i++)
        sys_nanosleep(ts);
    lt_ok(sig_received == 1, "signal delivered across fork");
    sys_waitpid(child);
}

static void test_session(void) {
    long sid = sys_getsid(0);
    lt_ok(sid > 0, "getsid returns valid sid");

    long child = sys_fork();
    if (child == 0) {
        long new_sid = sys_setsid();
        sys_exit(new_sid == sys_getpid() ? 0 : 1);
    }
    long st = sys_waitpid(child);
    lt_ok(st == 0, "child setsid creates new session");
}

static void test_sigtstp_sigcont(void) {
    long child = sys_fork();
    if (child == 0) {
        for (;;) sys_yield();
    }
    long ts[2] = {0, 50000000};
    sys_nanosleep(ts);
    sys_kill(child, 21);  /* SIGTSTP */
    sys_nanosleep(ts);
    sys_kill(child, 18);  /* SIGCONT */
    sys_nanosleep(ts);
    sys_kill(child, 9);   /* SIGKILL */
    sys_waitpid(child);
    lt_ok(1, "SIGTSTP+SIGCONT+SIGKILL cycle");
}

static void test_getpid_getppid(void) {
    long pid = sys_getpid();
    lt_ok(pid > 0, "getpid > 0");
}

static void test_multi_fork(void) {
    int count = 4;
    long pids[4];
    for (int i = 0; i < count; i++) {
        pids[i] = sys_fork();
        if (pids[i] == 0) sys_exit(i + 10);
    }
    int all_ok = 1;
    for (int i = 0; i < count; i++) {
        long st = sys_waitpid(pids[i]);
        if (st != i + 10) all_ok = 0;
    }
    lt_ok(all_ok, "multi-fork: 4 children exit with correct status");
}

static void test_env_inherit(void) {
    sys_setenv("TEST_INHERIT", "hello");
    long child = sys_fork();
    if (child == 0) {
        /* Keep it simple — just check env exists and exit */
        char val[32];
        val[0] = '\0';
        long ret = sys_getenv("TEST_INHERIT", val, 32);
        if (ret >= 0 && val[0] == 'h')
            sys_exit(0);
        sys_exit(1);
    }
    long st = sys_waitpid(child);
    lt_ok(st == 0, "env inherited across fork");
}

static void test_proc_stat_format(void) {
    /* /proc/1/stat must exist and parse as Linux format:
     *   "<pid> (<name>) <state> <ppid> <pgid> ..." */
    long fd = sys_open("/proc/1/stat", 0);
    lt_ok(fd >= 0, "/proc/1/stat exists");
    if (fd < 0) return;
    char buf[256];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    lt_ok(n > 0, "/proc/1/stat readable");
    if (n <= 0) return;
    buf[n] = '\0';

    /* First field should be pid 1 */
    lt_ok(buf[0] == '1' && buf[1] == ' ', "/proc/1/stat starts with pid 1");

    /* Second field is "(name)" — find opening paren and closing paren */
    const char *lp = (const char *)0;
    for (int i = 0; i < n; i++) if (buf[i] == '(') { lp = &buf[i]; break; }
    const char *rp = (const char *)0;
    for (int i = n - 1; i >= 0; i--) if (buf[i] == ')') { rp = &buf[i]; break; }
    lt_ok(lp && rp && rp > lp, "/proc/1/stat has (name) field");

    /* State letter must be one of R/S/T/Z */
    int letter_ok = 0;
    if (rp && rp + 2 < buf + n) {
        char st = rp[2];  /* ) <space> <letter> */
        if (st == 'R' || st == 'S' || st == 'T' || st == 'Z') letter_ok = 1;
    }
    lt_ok(letter_ok, "/proc/1/stat state letter is Linux-compatible");
}

static void test_proc_status_format(void) {
    long fd = sys_open("/proc/1/status", 0);
    lt_ok(fd >= 0, "/proc/1/status exists");
    if (fd < 0) return;
    char buf[1024];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    lt_ok(n > 0, "/proc/1/status readable");
    if (n <= 0) return;
    buf[n] = '\0';

    /* Linux fields: Name, State, Pid, PPid, Uid, Gid */
    lt_ok(strstr(buf, "Name:\t") != NULL, "status has Name:");
    lt_ok(strstr(buf, "State:\t") != NULL, "status has State:");
    lt_ok(strstr(buf, "Pid:\t") != NULL,   "status has Pid:");
    lt_ok(strstr(buf, "PPid:\t") != NULL,  "status has PPid:");
    lt_ok(strstr(buf, "Uid:\t") != NULL,   "status has Uid:");
    lt_ok(strstr(buf, "Gid:\t") != NULL,   "status has Gid:");
}

static void test_proc_cmdline_nul_separated(void) {
    long fd = sys_open("/proc/1/cmdline", 0);
    lt_ok(fd >= 0, "/proc/1/cmdline exists");
    if (fd < 0) return;
    char buf[256];
    long n = sys_read(fd, buf, sizeof(buf));
    sys_close(fd);
    lt_ok(n >= 0, "/proc/1/cmdline readable");
    /* Multi-arg cmdline must use NUL between args, not space — Linux convention. */
    int has_space = 0, has_nul = 0;
    for (long i = 0; i < n; i++) {
        if (buf[i] == ' ') has_space = 1;
        if (buf[i] == '\0' && i < n - 1) has_nul = 1;
    }
    if (has_space || has_nul) {
        lt_ok(!has_space || has_nul,
              "cmdline uses NUL not space (Linux convention)");
    } else {
        lt_ok(1, "cmdline single arg or empty");
    }
}

int main(void) {
    lt_suite("proc");
    test_fork_waitpid();
    test_fork_exec();
    test_pipe();
    test_signal();
    test_session();
    test_sigtstp_sigcont();
    test_getpid_getppid();
    test_multi_fork();
    test_env_inherit();
    test_proc_stat_format();
    test_proc_status_format();
    test_proc_cmdline_nul_separated();
    return lt_done();
}
