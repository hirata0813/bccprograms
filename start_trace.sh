#!/bin/bash -eu

#監視対象プログラムを起動
./tracing_targets.sh &

#監視対象プログラムのPIDを取得
shid=$(pgrep tracing_targets)

# 監視対象プログラムのPIDとともに，Pythonプログラムを起動
sudo ./ppidlist.py $shid 2> /dev/null

