// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   renoseven <dev@renoseven.net>
 *
 */

#include <linux/linkage.h>
#include <asm/unistd.h>

.text

ENTRY(__execve_syscall)
    mov     x8, __NR_execve
    svc     #0
    mov     x8, __NR_exit
    svc     #0
ENDPROC(__execve_syscall)

ENTRY(__exit_syscall)
    mov     x8, __NR_exit
    svc     #0
ENDPROC(__exit_syscall)
