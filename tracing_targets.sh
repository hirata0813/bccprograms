#!/bin/zsh -eu


sleep 2 #eBPFが起動するまで少し待つ
echo "Job Start"
python3 /home/hirata/git/examples/mnist/main.py > /dev/null #MNISTを動かす
#python3 /home/hirata/git/examples/mnist/main.py #MNISTを動かす
#ls > /dev/null 

# eBPFを停止
./stop_trace.sh
