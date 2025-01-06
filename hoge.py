#!/usr/bin/python3  

from bcc import BPF
from time import sleep
import ctypes
import subprocess
import socket

syscall_log = [] # ログを溜めていく変数

def get_syscalllog(bpf, data):
    # BPF MAP の内容を変数に代入
    event = bpf["events"].event(data)
    syscall = event.syscallnum
    pid = event.pid
    #print(f"SYSCALL:{syscall} PID:{pid} PATH1:{event.pathname1.decode()} PATH2:{event.pathname2.decode()}")
    syscall_log.append(syscall)

def get_and_send_state(sock, serv_address):
    # システムコールログを集約し，ジョブ状態を取得する
    state = get_state()

    if state:
        # ジョブ状態が取得できたらスケジューラに通知
        send_state(state, sock, serv_address)
    else: 
        # 取得できなければ何もしない
        return

def get_state():
    # システムコールログを集約
    # システムコールログが11個溜まったら通知する
    # システムコールが11個溜まったのを契機にジョブ状態取得
    if (len(syscall_log) == 11):
        state = "STATE-CHANGED"
        return state
    else:
        return None

def send_state(state, sock, serv_address):
    # 取得したジョブ状態をスケジューラに通知
    send_len = sock.sendto(str(state).encode('utf-8'), serv_address)
    print(f"Completed job state notification")
    # システムコールログの配列を空にする
    syscall_log.clear()

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
    bpf = BPF(src_file="./hoge.bpf.c")
    
    # ppidlistに監視対象プログラムのPIDを登録
    ppidlist = bpf.get_table("ppidlist")
    ppidlist[rootid] = ctypes.c_uint(0)
    
    # eBPFプログラムをkprobeにアタッチ
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="syscall__execve")
    #bpf.attach_kprobe(event=bpf.get_syscall_fnname("openat"), fn_name="syscall__openat")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("link"), fn_name="syscall__link")
    #bpf.attach_kprobe(event=bpf.get_syscall_fnname("unlink"), fn_name="syscall__unlink")

    M_SIZE = 1024
    
    # スケジューラが動作する計算機のアドレスを用意
    serv_address = ('127.0.0.1', 8890)
    
    # ソケットを作成する
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # ジョブ状態を格納する配列(第一要素：PID，第二要素：状態 みたいな)
    state = []
    
    
    def notify_jobstate(cpu, data, size):
        # BPF MAP にアクセスしシステムコール情報を取得
        get_syscalllog(bpf, data)

        # システムコールからジョブ状態を取得し，スケジューラに通知
        get_and_send_state(sock, serv_address)
    
    bpf["events"].open_perf_buffer(notify_jobstate)
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == '__main__':
    main()
