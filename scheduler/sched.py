#!/usr/bin/python3  

import socket
import os
import errno
import signal
import time
import json

# PID を受け取り，その PID を持つプロセスにシグナル送信
def send_signal(pid, signal):
    try:
        os.kill(int(pid), signal)
    except OSError as e:
        if e.errno != errno.ESRCH: #TODO: リファクタリング
            raise e

def suspend_process(t4, pid):
    try:
        send_signal(pid, signal.SIGSTOP)
        # t5: SIGSTOP send    
        t5 = time.clock_gettime_ns(time.CLOCK_MONOTONIC) * 10**(-9)

        # t4-5をファイルに出力
        with open("t4-5.csv","a") as f:
            print(f"{t4}, {t5}", file=f)
    
    except Exception as e:
        print(f"An error occurred: {e}")

def restart_process(pid):
    try:
        send_signal(pid, signal.SIGCONT)

    except Exception as e:
        print(f"An error occurred: {e}")

def switch_process(t4, pid):
    # ここでGPUプログラムの停止・再開を行う
    suspend_process(t4, pid)
    time.sleep(3)
    restart_process(pid)

def main():
    M_SIZE = 1024
    
    host = '127.0.0.1'
    port = 8890
    
    locaddr = (host, port)
    
    # ソケット作成
    sock = socket.socket(socket.AF_INET, type=socket.SOCK_DGRAM)
    
    # 自ホストで使用するIPアドレスとポート番号を指定
    sock.bind(locaddr)
    
    while True:
        try :
            # notifierからジョブ状態が送られてくるのを待つ
            state, cli_addr = sock.recvfrom(M_SIZE)

            # t4: job state 受け取り
            t4 = time.clock_gettime_ns(time.CLOCK_MONOTONIC) * 10**(-9)

            # 受信内容をデコード
            state_json = state.decode(encoding='utf-8')
            state_dict = json.loads(state_json)

            pid, stateid = state_dict['pidlist'][0], state_dict['stateid']
    
            if(stateid == 1):
                # stateid が 1 なら，control_process を呼んで，ジョブの一時停止，再開を行う
                switch_process(t4, pid)
    
        except KeyboardInterrupt:
            print ('\n . . .\n')
            sock.close()

if __name__ == '__main__':
    main()
