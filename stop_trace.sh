#!/bin/zsh -eu

#tracing_targets.shから呼び出してeBPFプログラムを停止する
#ebpfid=$(pgrep start_trace)
pythonid=$(pgrep notifier.py)
#sudo kill $ebpfid
sudo kill $pythonid
