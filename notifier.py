#!/usr/bin/python3  

from bcc import BPF
import time
import ctypes
import subprocess
import socket
import json
import os

syscall_log = [] # ログを溜めていく変数
pidlist = [] # ジョブのPIDを格納する変数，スケジューラに通知する用
ts = [0] * 5 # タイムスタンプ格納用の配列

def get_syscalllog(bpf, data):
    # BPF MAP にアクセスし，システムコールログを取得する関数
    event = bpf["events"].event(data)
    syscall = event.syscallnum
    pid = event.pid
    # t1: syscall 取得
    t1 = time.clock_gettime_ns(time.CLOCK_MONOTONIC) * 10**(-9)

    # t0: syscall 発行の瞬間
    t0 = event.time * 10**(-9)

    ts[0] = t0
    ts[1] = t1

    # BPF MAP の内容を変数に代入
    syscall_log.append(syscall)

    if pid not in pidlist:
        pidlist.append(pid)

def get_and_send_state(sock, serv_address):
    # システムコールからジョブ状態を取得し，スケジューラに通知する関数

    # ジョブ状態の取得
    state = get_state()

    if state:
        # ジョブ状態が取得できたらスケジューラに通知
        send_state(state, sock, serv_address)
    else: 
        # 取得できなければ何もしない
        return

def get_state():
    # システムコールログを集約し，ジョブ状態を取得する関数

    # システムコールが11個溜まったのを契機にジョブ状態取得
    if (len(syscall_log) == 11):
        # ジョブ状態の形式として，PIDと状態IDが必要
        # {'pid':xxxxx, 'stateid':1}的な

        state = {"pidlist":pidlist, "stateid":1}
        
        # t2: jobstate 取得
        t2 = time.clock_gettime_ns(time.CLOCK_MONOTONIC) * 10**(-9)
        ts[2] = t2

        return state
    else:
        return None

def send_state(state, sock, serv_address):
    # 取得したジョブ状態をスケジューラに通知する関数

    # エンコード
    stateToJson = json.dumps(state)
    stateToBin = stateToJson.encode('utf-8')
    
    # スケジューラに通知
    sock.sendto(stateToBin, serv_address)
    print(f"Completed job state notification")
    # t3: jobstate notify
    t3 = time.clock_gettime_ns(time.CLOCK_MONOTONIC) * 10**(-9)
    ts[3] = t3

    # t0-3をファイルに出力
    with open("t0-3.csv","a") as f:
        print(f"{ts[0]}, {ts[1]}, {ts[2]}, {ts[3]}", file=f)

    # システムコールログの配列を空にする
    syscall_log.clear()


def main():
    # ログファイルを削除
    if (os.path.isfile("./t0-3.csv")):
        os.remove("./t0-3.csv")
    if (os.path.isfile("./t4-5.csv")):
        os.remove("./t4-5.csv")
    if (os.path.isfile("./rootid.txt")):
        os.remove("./rootid.txt")

    # 監視対象プログラムを起動
    subprocess.run("./tracing_targets.sh &", shell=True)
    time.sleep(1)

    # 監視対象プログラムのPIDを取得
    subprocess.run("pgrep tracing_targets > rootid.txt", shell=True)
    rootid = int(open('rootid.txt', 'r', encoding='UTF-8').read()) # TODO: pgrep で複数の PID が取れる場合に対応させる
    rootid = ctypes.c_uint(rootid)
    subprocess.run("rm -rf rootid.txt", shell=True)
    
    # eBPFをロード
    bpf = BPF(src_file="./code.bpf.c")
    print("Load eBPF program")
    
    # ppidlistに監視対象プログラムのPIDを登録
    ppidlist = bpf.get_table("ppidlist")
    ppidlist[rootid] = ctypes.c_uint(0)
    
    # eBPFプログラムをkprobeにアタッチ
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="syscall__execve")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("link"), fn_name="syscall__link")

    # スケジューラが動作する計算機のIPアドレスを用意
    serv_address = ('127.0.0.1', 8890)
    
    # ソケット作成
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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
