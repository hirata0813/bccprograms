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

def suspend_process(pid):
    try:
        send_signal(pid, signal.SIGSTOP)
        print("Process has been suspended.")
        # t5: SIGSTOP send    
        t5 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)                
        print(f"T5: {t5}")

        # SIGSTOP送信時のタイムスタンプを取得
        #with open("sigstop.log","a") as f:
        #    print("{}".format(time.time()), file=f)
    
    except Exception as e:
        print(f"An error occurred: {e}")

def restart_process(pid):
    try:
        send_signal(pid, signal.SIGCONT)
        print("Process has been restarted.")
    
        # SIGCONT送信時のタイムスタンプを取得
        #with open("sigcont.log","a") as f:
        #    print("{}".format(time.time()), file=f)

    except Exception as e:
        print(f"An error occurred: {e}")

def control_process(pid):
    # ここでGPUプログラムの停止・再開を行う
    suspend_process(pid)
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
            # hogeからジョブ状態が送られてくるのを待つ
            print('Waiting message')
            state, cli_addr = sock.recvfrom(M_SIZE)
            print(f"Cli_addr:{cli_addr}")

            # 受信内容をデコード
            state_json = state.decode(encoding='utf-8')
            state_dict = json.loads(state_json)

            pid, stateid = state_dict['pidlist'][0], state_dict['stateid']
    
            if(stateid == 1):
                # stateid が 1 なら，control_process を呼んで，ジョブの一時停止，再開を行う
                control_process(pid)
                print('Completed job switching')
    
        except KeyboardInterrupt:
            print ('\n . . .\n')
            sock.close()

if __name__ == '__main__':
    main()
