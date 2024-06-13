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

#include "../../kselftest.h"

#define pr_p(func, fmt, ...) func("%s:%d: " fmt ": %m", \
                                __func__, __LINE__, ##__VA_ARGS__)

#define pr_err(fmt, ...)                                    \
	({                                                      \
		ksft_test_result_error(fmt "\n", ##__VA_ARGS__);    \
		-1;                                                 \
	})

#define pr_fail(fmt, ...)                                   \
	({                                                      \
		ksft_test_result_fail(fmt "\n", ##__VA_ARGS__);	    \
		-1;                                                 \
	})

#define pr_perror(fmt, ...)	pr_p(pr_err, fmt, ##__VA_ARGS__)

static inline int ptrace_and_wait(pid_t pid, int cmd, int sig)
{
	int status;

	/* Stop on syscall-exit. */
	if (ptrace(cmd, pid, 0, 0))
        return pr_perror("Can't resume the child %d", pid);
	if (waitpid(pid, &status, 0) != pid)
		return pr_perror("Can't wait for the child %d", pid);
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != sig)
		return pr_err("Unexpected status: %x", status);
	return 0;
}

static int child(int fd)
{
    char c;

    if (read(fd, &c, 1) != 1)
        return 1;

    return 0;
}

int main(int argc, char **argv)
{
    struct user_regs_struct regs;
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };
    int status;
    pid_t pid;
    int p[2], fdzero;

    ksft_set_plan(3);

    if (pipe(p))
        return pr_perror("Can't create a pipe");

    fdzero = open("/dev/zero", O_RDONLY);
    if (fdzero < 0)
        return pr_perror("Can't open /dev/zero");

    pid = fork();
    if (pid == 0) {
        kill(getpid(), SIGSTOP);
        return child(p[0]);
    }
    if (pid < 0)
        return 1;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0))
        return pr_perror("Can't attach to the child %d", pid);
    if (waitpid(pid, &status, 0) != pid)
        return pr_perror("Can't wait for the child %d", pid);

    /* Skip SIGSTOP */
    if (ptrace_and_wait(pid, PTRACE_CONT, SIGSTOP))
        return 1;

    /* Resume the child to the next system call */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Send a signal to interrupt the system call. */
    kill(pid, SIGUSR1);

    /* Stop on syscall-exit. */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))
		return pr_perror("Can't get child registers");
    if (regs.orig_a0 != p[0])
        return pr_fail("Unexpected a0: 0x%lx", regs.orig_a0);
    ksft_test_result_pass("orig_a0: 0x%lx\n", regs.orig_a0);

    printf("===============================================>\n");
    printf("regs.orig_a0: %lx\n", regs.orig_a0);
    printf("regs.a0: %lx\n", regs.a0);
    printf("===============================================>\n");

    /* Change orig_a0 that will be a0 for the restarted system call. */
    //regs.orig_a0 = fdzero;
    regs.a0 = fdzero;

    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov))
        return pr_perror("Can't get child registers");

    /* Trap the signal and skip it. */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGUSR1))
        return 1;

    /* Trap the restarted system call. */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Check that the syscall is started with the right first argument. */
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))
        return pr_perror("Can't get child registers");

    printf("===============================================>\n");
    printf("regs.orig_a0: %lx\n", regs.orig_a0);
    printf("regs.a0: %lx\n", regs.a0);
    printf("===============================================>\n");

    if (regs.a0 != fdzero)
        return pr_fail("unexpected a0: %lx", regs.a0);
    ksft_test_result_pass("a0: 0x%lx\n", regs.a0);

    printf("===============================================>\n");
    printf("regs.orig_a0: %lx\n", regs.orig_a0);
    printf("regs.a0: %lx\n", regs.a0);
    printf("===============================================>\n");

    if (ptrace(PTRACE_CONT, pid, 0, 0))
        return pr_perror("Can't resume the child %d", pid);
    if (waitpid(pid, &status, 0) != pid)
        return pr_perror("Can't wait for the child %d", pid);
    if (status != 0)
        return pr_fail("Child exited with code %d.", status);

    ksft_test_result_pass("The child exited with code 0.\n");
    ksft_exit_pass();
    return 0;
}