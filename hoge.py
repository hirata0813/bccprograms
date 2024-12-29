#!/usr/bin/python3  

from bcc import BPF
from time import sleep
import ctypes
import subprocess

def print_event(cpu, data, size):
    event = b["events"].event(data)
    syscall = event.syscallnum
    print(f"SYSCALL:{syscall}")
    #print(f"SYSCALL:{event.syscallnum} PATH1:{event.pathname1.decode()} PATH2:{event.pathname2.decode()}")

def main():
    # 監視対象プログラムを起動
    subprocess.run("./tracing_targets.sh &", shell=True)
    
    sleep(1)
    # 監視対象プログラムのPIDを取得
    subprocess.run("pgrep tracing_targets > rootid.txt", shell=True)
    rootid = int(open('rootid.txt', 'r', encoding='UTF-8').read()) # TODO: pgrep で複数の PID が取れる場合に対応させる
    rootid = ctypes.c_uint(rootid)
    subprocess.run("rm -rf rootid.txt", shell=True)
    
    
    # eBPFをロード
    b = BPF(src_file="./hoge.bpf.c")
    
    # ppidlistに監視対象プログラムのPIDを登録
    ppidlist = b.get_table("ppidlist")
    ppidlist[rootid] = ctypes.c_uint(0)
    
    # eBPFプログラムをkprobeにアタッチ
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
    b.attach_kprobe(event=b.get_syscall_fnname("link"), fn_name="syscall__link")
    b.attach_kprobe(event=b.get_syscall_fnname("unlink"), fn_name="syscall__unlink")
    
    
    
    b["events"].open_perf_buffer(print_event)
    while True:
        try:
            # BPF MAP の内容を変数に代入
            # 代入されたシステムコール情報を集約し，ジョブ状態を取得
            # 取得したジョブ状態をスケジューラに通知
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == '__main__':
    main()
