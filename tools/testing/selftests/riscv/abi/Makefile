# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 ARM Limited
# Originally tools/testing/arm64/abi/Makefile

CFLAGS += -I$(top_srcdir)/tools/include

TEST_GEN_PROGS := ptrace_restart_syscall_v0 ptrace_restart_syscall_v1 ptrace_restart_syscall_v2

include ../../lib.mk

$(OUTPUT)/ptrace_restart_syscall_v0: ptrace_restart_syscall_v0.c
	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^

$(OUTPUT)/ptrace_restart_syscall_v1: ptrace_restart_syscall_v1.c
	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^

$(OUTPUT)/ptrace_restart_syscall_v1: ptrace_restart_syscall_v1.c ptrace_restart_syscall_v2.c
$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
