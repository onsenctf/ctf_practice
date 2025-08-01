# SHA-1 is dead
[問題文](https://github.com/SECCON/SECCON2017_online_CTF/blob/master/crypto/100_SHA-1%20is%20dead/question.txt)
> SHA-1 is dead
> http://sha1.pwn.seccon.jp/
> Upload two files satisfy following conditions:
> 	
> 1. file1 != file2
> 2. SHA1(file1) == SHA1(file2)
> 3. SHA256(file1) <> SHA256(file2)
> 4. 2017KiB < sizeof(file1) < 2018KiB
> 5. 2017KiB < sizeof(file2) < 2018KiB
> * 1KiB = 1024 bytes

## 概要
- アーカイブレポジトリは[こちら](https://github.com/SECCON/SECCON2017_online_CTF/tree/master/crypto/100_SHA-1%20is%20dead)
  - `answer.txt`: 作問者writeup
  - `flag.txt`: 答え
  - `question.txt`: 問題文

- SHA-1に対し衝突攻撃を行い，ハッシュ値が一致する異なる2つのファイルを作成する．
  - ファイルサイズを問題が期待するものに変更する必要がある

- 以下，file1とfile2をアップロードするページを「提出ページ」と呼ぶ．

## 当日の環境の再現
できる人は読み飛ばしてもらって構わない．

先のリポジトリの[build](https://github.com/SECCON/SECCON2017_online_CTF/tree/master/crypto/100_SHA-1%20is%20dead/build)
ディレクトリをローカルに落としてきて`bash run.sh`とした後，http://localhost:80 にアクセスすると，提出ページが現れる．

## 解答
### 1. 問題文を読む
- SHA-1 is dead というタイトル
- 問題文の条件2. SHA1(file1) == SHA1(file2)
などから，SHA-1に対する**衝突攻撃**を行うことを思いつく．

### 2. SHA-1　衝突　でググる
SHA-1に対して過去に行われた衝突攻撃があるかを調べる．
すると，[こんなページ](https://developers-jp.googleblog.com/2017/03/announcing-first-sha1-collision.html)がヒットする．

さらに「PDF」で`Ctrl-f`してみると，[衝突攻撃に成功したPDF](https://shattered.it/)が得られることが分かった．

### 3. ファイルサイズを適宜変更する
2017KiB < filesize < 2018KiB となるよう，パディングを行えばよい．



### おまけ. 衝突攻撃の計算時間を概算してみる
まず，提出ページでアップロードする`file1`および`file2`の容量は2017KB ~ 2018KBであることから，以下のように`file1`, `file2`を構成することを考え付いた：
  1. 先頭2017KBは`file1`, `file2`で共通
  2. 残りの1KB分の余地を使って，うまい具合にSHA-1値が衝突するようなものを発見する．

ここで，上の方法の2. における探索時間はどれくらいかかるのだろうか．
愚直にブルートフォースを行うのであれば，...

もう少し楽観的な探索時間の概算方法として，**誕生日のパラドックス**に基づいて計測することを考える．
誕生日のパラドックスとは，「ある学校のクラスで，**誕生日が全員異なる確率**が，直感に反する程度に低いこと」を表現した言葉である．
例えば40人のクラスで，全員の誕生日が異なる確率は0.09程度である．
つまり，約0.9の確率でクラスの誰かしらは誕生日が被るということになる．

さて，上の例では，**Y = 全365通り**の誕生日の候補に対して**D = 40通り**の誕生日を任意に取ってくると，大体**0.9**の確率で誰かしらは被る（= **衝突する**)のだった．
一般に，「D = sqrt(Y)の時，約1/2の確率で衝突する」という事実が成り立つことが知られている．

この事実をそのまま引き継ぎ，SHA-1の場合を考える．



## 関連知識
- `sha1sum`コマンド

--- 

## 所感
- 簡単
