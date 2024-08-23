#!/usr/bin/python3  
from bcc import BPF
from time import sleep
import ctypes
import subprocess

# 監視対象プログラムを起動
subprocess.run("./tracing_targets.sh &", shell=True)

# 監視対象プログラムのPIDを取得
subprocess.run("pgrep tracing_targets > rootid.txt", shell=True)
rootid = int(open('rootid.txt', 'r', encoding='UTF-8').read())
rootid = ctypes.c_uint(rootid)
subprocess.run("rm -rf rootid.txt", shell=True)


# 取得したPIDとともにBCCをロード
b = BPF(src_file="./ppidlist.bpf.c")

# ppidlistに監視対象プログラムのPIDを登録
ppidlist = b.get_table("ppidlist")
ppidlist[rootid] = ctypes.c_uint(0)

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

