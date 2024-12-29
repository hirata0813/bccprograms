#!/bin/bash -eu


sleep 5 #eBPFが起動するまで少し待つ
#python3 /home/hirata/git/examples/mnist/main.py > /dev/null #MNISTを動かす
ls > /dev/null 

# eBPFを停止
#./stop_trace.sh
