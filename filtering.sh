#!/bin/bash -eu

# 自身のPIDを取得
shid=$$

# トレース用eBPFプログラムを起動
sudo /home/hirata/bccprograms/ppid-candidates.py $shid &

# トレース対象のプログラムを起動
ls

# eBPFプログラムを終了
sudo kill $(ps -C ppid-candidates -o pid=)
