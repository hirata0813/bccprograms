#!/usr/bin/python3  
from bcc import BPF
from time import sleep
import sys
import ctypes

program = r"""
#include <linux/sched.h>

// トレースするプロセスを指定するためのハッシュテーブルを定義
// シェルスクリプト内で生成されたプロセス(つまり親プロセスになりうるプロセス)のPIDを保持する
// ppid_candidates内に格納されているPPIDを持つプロセスのみを監視する
BPF_HASH(ppid_candidates, int, int); 

int trace_execve(void *ctx){
    //execveが発行されたら，そのプロセスの親プロセスが何かを判定し，PIDをppid_candidatesに書き込む
    int ppid;
    int pid;
    int *p;
    int dummy=0;

    ppid = ((struct task_struct *)bpf_get_current_task())->real_parent->tgid;
    p = ppid_candidates.lookup(&ppid);

    if(p != 0){//ppid_candidates内にPPIDが存在した場合
               //そのプロセスはトレース対象である
        pid = bpf_get_current_pid_tgid() >> 32;
        ppid_candidates.update(&pid, &ppid); //PIDを登録
    }
    return 0;
}
"""

b = BPF(text=program)

# 大元のプロセス(このプロセスの親プロセス)のPIDを登録
# これは第一引数で渡す
args = sys.argv
shid = int(args[1])
shid = ctypes.c_uint(shid)
ppid_candidates = b.get_table("ppid_candidates")
ppid_candidates[shid] = ctypes.c_uint(0);



execve_syscall = b.get_syscall_fnname("execve")

b.attach_kprobe(event=execve_syscall, fn_name="trace_execve")
print("PID PPID")

while True:
     sleep(2)
     s = ""
     for ppid,value in ppid_candidates.items():
         s += f"PID {ppid.value} PPID{value.value}\n"
     print(s)

