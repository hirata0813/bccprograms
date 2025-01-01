#!/usr/bin/python3  

import socket
import os
import errno
import signal
import time

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
    
    # 
    host = '127.0.0.1'
    port = 8890
    
    locaddr = (host, port)
    
    # ①ソケットを作成する
    sock = socket.socket(socket.AF_INET, type=socket.SOCK_DGRAM)
    print('create socket')
    
    # ②自ホストで使用するIPアドレスとポート番号を指定
    sock.bind(locaddr)
    
    while True:
        try :
            # hogeからジョブ状態が送られてくるのを待つ
            print('Waiting message')
            state, cli_addr = sock.recvfrom(M_SIZE)
            state = state.decode(encoding='utf-8')
            print(f'Received message is [{state}]')
            pid = int(state[0])
    
            # ジョブ状態を受け取ったら，該当ジョブにシグナルを送信し，再度 hoge からの通知を待つ
            # ジョブを一時停止，ある程度時間が経過したら再開
            # ジョブを識別する PID はこのタイミングでもらう
            control_process(pid)
            print('Completed job switching')
    
    
        except KeyboardInterrupt:
            print ('\n . . .\n')
            sock.close()

if __name__ == '__main__':
    main()
