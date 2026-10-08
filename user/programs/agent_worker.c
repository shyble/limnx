/*
 * agent_worker.c — Worker agent for orchestration demo
 *
 * Launched by orchestrator via supervisor. Discovers task/result topics
 * by well-known IDs (0=tasks, 1=results). Registers with agent registry,
 * processes tasks by calling inference, publishes results via pub/sub.
 */

#include "../libc/libc.h"
#include "limnx/syscall_nr.h"

int main(void) {
    long my_pid = sys_getpid();

    /* Worker ID derived from PID (simple, unique per worker) */
    int worker_id = (int)(my_pid % 100);

    printf("[worker %d] pid=%ld starting\n", worker_id, my_pid);

    /* Register with agent registry */
    char name[32];
    int nlen = 0;
    const char *pfx = "worker_";
    while (*pfx) name[nlen++] = *pfx++;
    name[nlen++] = '0' + (char)(worker_id % 10);
    name[nlen] = '\0';
    sys_agent_register(name);

    /* Subscribe to results topic (ID 1 — created by orchestrator) */
    long result_topic = 1;
    sys_topic_subscribe(result_topic);

    /* Subscribe to tasks topic (ID 0 — created by orchestrator) */
    long task_topic = 0;
    sys_topic_subscribe(task_topic);

    /* Apply seccomp sandbox — arch-aware syscall bitmask.
     * Uses SYS_* macros which resolve to correct numbers per arch.
     * All Limnx syscalls (512+) pass through automatically. */
    {
        unsigned long filter[SECCOMP_FILTER_WORDS] = {0};
        #define ALLOW(nr) SECCOMP_ALLOW(filter, nr)

        ALLOW(SYS_READ);           /* read from fd */
        ALLOW(SYS_WRITE);          /* write to fd */
        ALLOW(SYS_CLOSE);          /* close fd */
        ALLOW(SYS_FSTAT);          /* stat by fd */
        ALLOW(SYS_MMAP);           /* memory mapping */
        ALLOW(SYS_MUNMAP);         /* unmap */
        ALLOW(SYS_BRK);            /* heap */
        ALLOW(SYS_RT_SIGACTION);   /* signal handlers */
        /* RT_SIGRETURN + EXIT always bypassed by kernel seccomp */
        ALLOW(SYS_IOCTL);          /* terminal (printf) */
        ALLOW(SYS_WRITEV);         /* vectored write */
        ALLOW(SYS_SCHED_YIELD);    /* cooperative yield */
        ALLOW(SYS_NANOSLEEP);      /* sleep */
        ALLOW(SYS_GETPID);         /* identity */
        ALLOW(SYS_EXIT);           /* exit */
        ALLOW(SYS_EXIT_GROUP);     /* exit group */
        ALLOW(SYS_SECCOMP);        /* allow seccomp itself (can only narrow) */
        ALLOW(SYS_PPOLL);          /* poll (ARM64 uses ppoll) */
        #ifdef SYS_POLL
        ALLOW(SYS_POLL);           /* poll (x86_64 has native poll) */
        #endif

        #undef ALLOW
        sys_seccomp_filter(filter, 1 /* strict */);
        printf("[worker %d] seccomp sandbox active\n", worker_id);
    }

    /* Process tasks */
    int tasks_done = 0;
    for (int attempt = 0; attempt < 200; attempt++) {
        /* Try to receive a task assignment from task topic */
        char task_buf[256];
        unsigned long sender_pid = 0;
        long n = sys_topic_recv(task_topic, task_buf, sizeof(task_buf) - 1,
                                &sender_pid);

        if (n <= 0) {
            /* No task available — yield and retry */
            sys_yield();
            continue;
        }

        task_buf[n] = '\0';
        printf("[worker %d] Got task: %s\n", worker_id, task_buf);

        /* Check for DONE signal */
        if (n >= 4 && task_buf[0] == 'D' && task_buf[1] == 'O' &&
            task_buf[2] == 'N' && task_buf[3] == 'E') break;

        /* Parse task: "TASK:<task_id>:<prompt>" */
        long task_id = -1;
        char *prompt = task_buf;
        if (n >= 5 && task_buf[0] == 'T' && task_buf[4] == ':') {
            task_id = 0;
            int i = 5;
            while (task_buf[i] >= '0' && task_buf[i] <= '9') {
                task_id = task_id * 10 + (task_buf[i] - '0');
                i++;
            }
            if (task_buf[i] == ':') i++;
            prompt = &task_buf[i];
        }

        /* Check if another worker already completed this task */
        if (task_id >= 0) {
            task_status_t ts;
            if (sys_task_status(task_id, &ts) == 0 && ts.status >= TASK_DONE) {
                continue;  /* already done by another worker */
            }
        }

        /* Call inference service */
        char resp[256];
        long rlen = sys_infer_request("default", prompt, strlen(prompt),
                                      resp, sizeof(resp) - 1);

        /* Build result: "RESULT:<worker_id>:<task_id>:<response>" */
        char result[384];
        int rpos = 0;
        const char *rpfx = "RESULT:";
        while (*rpfx) result[rpos++] = *rpfx++;
        result[rpos++] = '0' + (char)(worker_id % 10);
        result[rpos++] = ':';

        /* Append task_id */
        if (task_id >= 0) {
            char tmp[16]; int tlen = 0;
            long v = task_id;
            if (v == 0) { tmp[tlen++] = '0'; }
            else { while (v > 0) { tmp[tlen++] = '0' + (int)(v % 10); v /= 10; } }
            for (int j = tlen - 1; j >= 0; j--) result[rpos++] = tmp[j];
        } else {
            result[rpos++] = '?';
        }
        result[rpos++] = ':';

        /* Append response */
        if (rlen > 0) {
            resp[rlen] = '\0';
            int copylen = (int)rlen;
            if (rpos + copylen > 380) copylen = 380 - rpos;
            for (int j = 0; j < copylen; j++) result[rpos++] = resp[j];
        } else {
            const char *fb = "(processed locally)";
            while (*fb && rpos < 380) result[rpos++] = *fb++;
        }
        result[rpos] = '\0';

        /* Publish result */
        sys_topic_publish(result_topic, result, (unsigned long)rpos);
        printf("[worker %d] Completed task %ld\n", worker_id, task_id);

        /* Mark task complete in the task graph */
        if (task_id >= 0)
            sys_task_complete(task_id, 0);

        tasks_done++;
    }

    printf("[worker %d] Exiting after %d tasks\n", worker_id, tasks_done);
    return 0;
}
