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

static inline int ptrace_and_wait(pid_t pid, int flag, int sig)
{
	int status;

	/* Stop on syscall-exit. */
	if (ptrace(flag, pid, 0, 0)) {
        ksft_test_result_error("failed to resume the tracee %d\n", pid);
        return -1;
    }

	if (waitpid(pid, &status, 0) != pid) {
        ksft_test_result_error("failed to wait for the tracee %d\n", pid);
    }

	if (!WIFSTOPPED(status) || WSTOPSIG(status) != sig) {
        ksft_test_result_error("unexpected status: %x\n", status);
    }

	return 0;
}

static int tracee(int fd)
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
    int fd_zero, fd_null;

    ksft_set_plan(3);

    fd_null = open("/dev/null", O_RDONLY);
    if (fd_null < 0) {
        ksft_test_result_error("failed to open /dev/null\n");
        return -1;
    }

    fd_zero = open("/dev/zero", O_RDONLY);
    if (fd_zero < 0) {
        ksft_test_result_error("failed to open /dev/zero\n");
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        /*
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
            ksft_test_result_error("failed to establish a tracing relationship\n");
            return -1;
        }
        */

        kill(getpid(), SIGSTOP);
        return tracee(fd_null);
    }
    if (pid < 0)
        return 1;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        ksft_test_result_error("failed to attach to the tracee %d\n", pid);
        return -1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        ksft_test_result_error("failed to wait for the child %d\n", pid);
        return -1;
    }

    /* Skip SIGSTOP */
    if (ptrace_and_wait(pid, PTRACE_CONT, SIGSTOP))
        return 1;

    /* Resume the tracee to the next system call */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Send a signal to interrupt the system call. */
    kill(pid, SIGUSR1);

    /* Stop on syscall-exit. */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Check that the syscall is started with the right first argument. */
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
        ksft_test_result_error("failed to get tracee registers\n");
        return -1;
    }
    if (regs.orig_a0 != fd_null) {
        ksft_test_result_fail("unexpected orig_a0: 0x%lx\n", regs.orig_a0);
        return -1;
    }
    ksft_test_result_pass("orig_a0: 0x%lx\n", regs.orig_a0);

    /* Change orig_a0 that will be a0 for the restarted system call. */
    regs.orig_a0 = fd_zero;
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov)) {
        ksft_test_result_error("failed to set tracee registers\n");
        return -1;
    }

    /* Trap the signal and skip it. */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGUSR1))
        return 1;

    /* Trap the restarted system call. */
    if (ptrace_and_wait(pid, PTRACE_SYSCALL, SIGTRAP))
        return 1;

    /* Check that the syscall is restarted with the right first argument. */
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
        ksft_test_result_error("failed to get tracee registers\n");
        return -1;
    }
    if (regs.a0 != fd_zero) {
        ksft_test_result_fail("unexpected regs.a0: 0x%lx\n", regs.a0);
        return -1;
    }
    ksft_test_result_pass("a0: 0x%lx\n", regs.a0);

    /* Check exit status of the tracee */
    if (ptrace(PTRACE_CONT, pid, 0, 0)) {
        ksft_test_result_error("failed to resume to the tracee %d\n", pid);
        return -1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        ksft_test_result_error("failed to wait for the tracee %d\n", pid);
        return -1;
    }
    if (status != 0) {
        ksft_test_result_fail("tracee exited with code %d\n", status);
        return -1;
    }

    ksft_test_result_pass("tracee exited with code 0\n");
    ksft_exit_pass();

    close(fd_null);
    close(fd_zero);

    return 0;
}