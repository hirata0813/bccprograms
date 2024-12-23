#!/bin/bash -eu


sleep 5 #eBPFが起動するまで少し待つ
python3 /home/hirata/git/examples/mnist/main.py > /dev/null #MNISTを動かす

# eBPFを停止
#./stop_trace.sh
