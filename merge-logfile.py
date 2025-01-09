#! /usr/bin/python3

import sys
import pandas as pd

# CSVファイルのパスを指定
csv_file_1 = sys.argv[1]  # 1つ目のCSVファイル
csv_file_2 = sys.argv[2]  # 2つ目のCSVファイル

# CSVファイルを読み込む
df1 = pd.read_csv(csv_file_1)
df2 = pd.read_csv(csv_file_2)

# CSVファイルを結合 (列方向または行方向で結合可能)
# 列方向に結合（横に結合）
combined_df = pd.concat([df1, df2], axis=1)

# 結合結果を新しいCSVファイルとして保存
combined_df.to_csv('ts.csv', index=False)

