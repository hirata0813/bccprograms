#!/usr/bin/python3  
from bcc import BPF
from time import sleep
import sys
import ctypes

b = BPF(src_file="./ppidlist.bpf.c")

# 大元のプロセス(このプロセスの親プロセス)のPIDを登録
# これは第一引数で渡す
args = sys.argv
shid = int(args[1])
shid = ctypes.c_uint(shid)
ppidlist = b.get_table("ppidlist")
ppidlist[shid] = ctypes.c_uint(0)

# eBPFプログラムをkprobeにアタッチ
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="trace_open")


print("PID      PPID     COMM")
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("{:<8} {:<8} {:16}".format(event.pid, event.ppid, event.comm.decode()))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

