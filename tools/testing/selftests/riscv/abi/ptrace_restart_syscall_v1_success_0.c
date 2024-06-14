// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <linux/unistd.h>
#include <asm/ptrace.h>

#include "../../kselftest_harness.h"

#define ORIG_A0_BEFORE_MODIFIED     0x3
#define ORIG_A0_AFTER_MODIFIED      0x5
#define MODIFY_A0_CASE              0x01
#define MODIFY_ORIG_A0_CASE         0x02

#define log_err(fmt, ...) do {                  \
    char buffer[256];                           \
    snprintf(buffer, sizeof(buffer),            \
            "%s:%d: " fmt ": %m\n",               \
            __func__, __LINE__, __VA_ARGS__);   \
    perror(buffer);                             \
} while (0)

static inline int resume_and_wait_child(pid_t pid, int flag, int sig)
{
    int status;

    if (ptrace(flag, pid, 0, 0))
        log_err("failed to resume the tracee %d", pid);

    if (waitpid(pid, &status, 0) != pid) {
        perror("wait for the tracee failed");
        return -1;
    }

    return 0;
}

static int ptrace_restart_syscall_test(int opt, int *result)
{
    int status;
    int p[2], fd_zero;
    pid_t pid;
    struct user_regs_struct regs;
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (pipe(p)) {
        perror("create a pipe failed");
        return -1;
    }

    fd_zero = open("/dev/zero", O_RDONLY);
    if (fd_zero < 0) {
        perror("open /dev/zero failed");
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        char c;
        
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
            perror("request for tracer to trace me failed");
            return -1;
        }
        kill(getpid(), SIGSTOP);
        
        if (read(p[0], &c, 1) != 1)
            return 1;

        return 0;
    } else if (pid < 0)
        return 1;

    /*
    if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        ksft_test_result_error("failed to attach to the tracee %d\n", pid);
        return -1;
    }
    */

    printf("i am coming !!!\n");
    if (waitpid(pid, &status, 0) != pid) {
        ksft_test_result_error("failed to wait for the tracee %d\n", pid);
        return -1;
    }


    /* Resume the tracee to the next system call */
    if (resume_and_wait_child(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Send a signal to interrupt the system call. */
    kill(pid, SIGUSR1);

    /* Stop on syscall-exit. */
    if (resume_and_wait_child(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
        perror("get child registers failed");
        return -1;
    }

    printf("==========================================>\n");
    printf("orig_a0: %lx\n",regs.orig_a0);
    printf("a0: %lx\n",regs.a0);
    printf("==========================================>\n");

    if (regs.orig_a0 != p[0]) {
        perror("unexpected a0");
        return -1;
    }

    /* Change a0/orig_a0 that will be a0 for the restarted system call. */
    switch (opt) {
    case MODIFY_A0_CASE: {
        regs.a0 = fd_zero;
        break;
    }
    case MODIFY_ORIG_A0_CASE:
        regs.orig_a0 = fd_zero;
        break;
    }

    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov)) {
        perror("set tracee registers failed");
        return -1;
    }

    /* Trap the signal and skip it. */
    if (resume_and_wait_child(pid, PTRACE_SYSCALL, SIGUSR1))
        return 1;

    /* Trap the restarted system call. */
    if (resume_and_wait_child(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Check that the syscall is started with the right first argument. */
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
        perror("get child registers failed");
        return -1;
    }

    printf("==========================================>\n");
    printf("orig_a0: %lx\n",regs.orig_a0);
    printf("a0: %lx\n",regs.a0);
    printf("==========================================>\n");

    *result = regs.a0;

    if (ptrace(PTRACE_CONT, pid, 0, 0)) {
        perror("resume the tracee failed");
        return -1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        perror("wait for the tracee failed");
        return -1;
    }
    if (status != 0) {
        perror("unexpected exit status");
        return -1;
    }
    
    return 0;
}

TEST(ptrace_modify_a0)
{
    int result;

    ptrace_restart_syscall_test(MODIFY_A0_CASE, &result);

    EXPECT_NE(ORIG_A0_AFTER_MODIFIED, result);
}

TEST(ptrace_modify_orig_a0)
{
    int result;

    ptrace_restart_syscall_test(MODIFY_ORIG_A0_CASE, &result);

    EXPECT_EQ(ORIG_A0_AFTER_MODIFIED, result);
}

TEST_HARNESS_MAIN
