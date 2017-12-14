#!/usr/bin/python

from __future__ import print_function
from bcc import BPF

REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/spinlock_types.h>
#include <linux/delayacct.h>
#include <linux/sched.h>

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

void trace_completion(struct pt_regs *ctx, u64* start, u64* total, u32* count) {
	struct task_delay_info * delays = container_of(start, struct task_delay_info, blkio_start);
	bpf_trace_printk("Updating stats at: %p\\n", delays);
}
""")

b.attach_kprobe(event="delayacct_end", fn_name="trace_completion")

# format output
while True:
	b.trace_print()
