#ifndef __BPF_DAEMON_H
#define __BPF_DAEMON_H

#include "vmlinux.h"

#define ARGSIZE 128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t)-1)
#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 uid;
    u32 retval;
    u8 args_count;
    u16 args_size;
    char args[FULL_MAX_ARGS_ARR];
} __attribute__((packed));

#endif /* __BPF_DAEMON_H */
