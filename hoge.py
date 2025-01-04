#!/usr/bin/python3  

from bcc import BPF
from time import sleep
import ctypes
import subprocess
import socket

def get_and_send_state(syscalllog, sock, serv_address):
    # システムコールログを集約

    # ジョブ状態が取得できたらスケジューラに通知
        send_state(state, sock, serv_address)
    # 取得できなければ何もしない

def get_syscalllog(bpf, data):
    # BPF MAP の内容を変数に代入
    # 0.01sおきにMAPを読みに行く
    event = bpf["events"].event(data)
    syscall = event.syscallnum
    pid = event.pid
    #print(f"SYSCALL:{syscall} PID:{pid} PATH1:{event.pathname1.decode()} PATH2:{event.pathname2.decode()}")
    print(syscall)


def send_state(state, sock, serv_address):
    sleep(1)
    # 取得したジョブ状態をスケジューラに通知
    send_len = sock.sendto(str(syscall).encode('utf-8'), serv_address)
    print(f"Completed job state notification")

def get_state_from_syscall():
    # 代入されたシステムコール情報を集約し，ジョブ状態を取得
    # システムコール
    # linkの発行を契機にジョブ切替
    sleep(1)

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
        syscalllog = get_syscalllog(bpf, data)

        # システムコールからジョブ状態を取得し，スケジューラに通知
        #get_and_send_state(syscalllog, sock, serv_address)
    
    bpf["events"].open_perf_buffer(notify_jobstate)
    cnt = 0
    while True:
        try:
            # この書き方だと，MAPに書き足された回数コールバックが呼ばれる
            # stateの通知は1回だけしたいので，perf_buffer_pollはあまりよろしくないかも
            # pythonのapiで定期的にMAPを読みに行くのがまるそう
            # あるいは，(現時点では)コールバックとして以下の処理
                # 1. システムコールログを取得
                # 2. ログを別の変数かファイルに書き出す
            # やっぱり制御が難しいから，今後のことを考えても定期的に読みに行くのがよい？

            bpf.perf_buffer_poll()
            print(f"Loop:{cnt}")
            cnt = cnt + 1
            # cnt が特定の回数(11回)呼ばれたら通知するとか
        except KeyboardInterrupt:
            exit()

if __name__ == '__main__':
    main()
