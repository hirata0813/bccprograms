#!/usr/bin/python3  

from bcc import BPF
from time import sleep
import ctypes
import subprocess

# 監視対象プログラムを起動
subprocess.run("./tracing_targets.sh &", shell=True)
#subprocess.run("python3 /home/hirata/git/examples/mnist/main.py &", shell=True)

sleep(1)
# 監視対象プログラムのPIDを取得
subprocess.run("pgrep tracing_targets > rootid.txt", shell=True)
#subprocess.run("pgrep -o main > rootid.txt", shell=True)
rootid = int(open('rootid.txt', 'r', encoding='UTF-8').read()) # TODO: pgrep で複数の PID が取れる場合に対応させる
rootid = ctypes.c_uint(rootid)
subprocess.run("rm -rf rootid.txt", shell=True)


# eBPFをロード
b = BPF(src_file="./ppidlist.bpf.c")

# ppidlistに監視対象プログラムのPIDを登録
ppidlist = b.get_table("ppidlist")
ppidlist[rootid] = ctypes.c_uint(0)

# eBPFプログラムをkprobeにアタッチ
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
b.attach_kprobe(event=b.get_syscall_fnname("link"), fn_name="syscall__link")
b.attach_kprobe(event=b.get_syscall_fnname("unlink"), fn_name="syscall__unlink")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("SYSCALL:{} PATH1:{} PATH2:{}".format(event.syscallnum, event.pathname1.decode(), event.pathname2.decode()))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

