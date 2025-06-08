# ctf_practice

## はじめに
このリポジトリは，チームで参加したCTF のWriteup や，CTF で使うツールの使い方をまとめたリポジトリです．

## 貢献のやり方
- 問題のカテゴリごとにディレクトリを作成しているので，それぞれの直下に`CTFの名前のディレクトリ`を作成してください．
- さらに問題ごとにディレクトリを作成し，直下に問題内容とWriteupへのリンクを記した `README.md` を作成してください．( `README.md` にはネタバレを載せないようにしましょう)
- 以下は，ある問題のディレクトリ構成です．このように， `Writeup` や `solver` を含むネタバレファイルは `solve` というディレクトリに置いておきましょう．

    ```
    .
    ├── README.md
    ├── assets
    │   ├── ghidra_asm.png
    │   ├── ghidra_asm2.png
    │   ├── ghidra_compare.png
    │   └── ghidra_main.png
    └── solve
        ├── solve.py
        └── writeup.md

    ```
- writeupを書く際に必要になった画像ファイルなどは， `assets` ディレクトリに置きましょう．

## テンプレート作成ツール

このリポジトリには、CTFのWriteup用ディレクトリとファイルを自動生成するツール `writeup` が含まれています。

### インストール方法

1. `~/opt/bin` ディレクトリをPATHに追加します：
   ```bash
   # .bashrc または .zshrc に追加
   export PATH="$HOME/opt/bin:$PATH"
   ```

2. シェルを再起動するか、設定ファイルを再読み込みします：
   ```bash
   source ~/.bashrc
   ```

3. ツールをインストールします：
   ```bash
   cd utils
   make
   ```

### 使い方

#### 1. CTFイベント用ディレクトリの初期化

```bash
writeup init GENRE/EVENT_NAME
```

- `GENRE`: `crypto`, `forensics`, `misc`, `osint`, `pwn`, `reversing`, `web` のいずれか
- `EVENT_NAME`: CTFイベント名（例: `hoge_CTF_2023`）

例：
```bash
writeup init crypto/hoge_CTF_2023
```

#### 2. 問題用テンプレートの生成

```bash
cd GENRE/EVENT_NAME
writeup add CHALLENGE_NAME
```

例：
```bash
cd crypto/hoge_CTF_2023
writeup add My_Question1
```

このコマンドにより、以下の構造が自動生成されます：
```
My_Question1/
├── README.md          # 問題の概要とSolutionへのリンク
├── given_files/       # 問題ファイル置き場
├── assets/           # Writeup用画像ファイル置き場
└── solve/
    └── writeup.md    # 解法の詳細
```

### アンインストール

```bash
cd utils
make clean
```