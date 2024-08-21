#!/bin/bash -eu


sleep 5 #eBPFが起動するまで少し待つ
echo "Tracing Targets Start"
sleep 10
cat test.txt
echo "Tracing Targets End"

# eBPFを停止
#./stop_trace.sh
