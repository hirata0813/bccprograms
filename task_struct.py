#!/usr/bin/python3
from bcc import BPF
import ctypes

bpf_text="""
#include <linux/sched.h>
#include <linux/cgroup.h>
#include <linux/cgroup-defs.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char fname[128];
};
BPF_PERF_OUTPUT(events);

BPF_HASH(table, struct cgroup*, int);

int syscall__execve(struct pt_regs *ctx, const char __user *filename)
{
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct css_set *cssset = task->cgroups;
    struct cgroup_subsys_state *css = cssset->subsys[0];
    struct cgroup *cgrp = css->cgroup; //同じcgroupの場合，構造体のポインタも同じになっている
    int *p;
    int count=1;


    p = table.lookup(&cgrp); //ポインタがMAPに登録されているかチェック，登録されているならそれは監視対象

    if(p == 0){
        table.update(&cgrp, &count);
    }else{
        //valueを取得して1増やして更新
        count=*p;
        count++;
        table.update(&cgrp, &count);
    }

    //if(p != 0){ 
    //監視対象に対しての処理
    //}
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;


    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(data.fname, sizeof(data.fname), (void *)filename);

    events.perf_submit(ctx, &data, sizeof(struct data_t));
    
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

print("PID      PPID     COMM             FNAME")
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("{:<8} {:<8} {:16} {}".format(event.pid, event.ppid, event.comm.decode(), event.fname.decode()))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
