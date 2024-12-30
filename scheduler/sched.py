


#!/usr/bin/python3  
import socket
import time

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
        message, cli_addr = sock.recvfrom(M_SIZE)
        message = message.decode(encoding='utf-8')
        print(f'Received message is [{message}]')

        # ジョブ状態を受け取ったら，該当ジョブにシグナルを送信し，再度 hoge からの通知を待つ

    except KeyboardInterrupt:
        print ('\n . . .\n')
        sock.close()
