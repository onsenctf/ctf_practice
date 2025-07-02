logins配列に対して，入力されたインデックスの値が"admin"となるようにする問題．
つまり，main関数内の変数indexが7となれば良い．

そこで，入力を受け付けいているread_int_lower_than関数に注目する．
しかし，ここではNUM_USERS-1 = 7以上の値が入力されると，プログラム終了してしまう．

```
unsigned short idx = read_int_lower_than(NUM_USERS - 1);
```
そこで以上の箇所に注目すると，関数read_int_lower_thanの返り値の型がintである一方，関数main内で定義されている変数idxの型はunsigned shortであることがわかる．
つまり，idxは0から65535の範囲であり，mod 65536を取った値に変換される．

そこで，7未満であり，かつ65536でmodを取ると7になる数字を入力すれは良い．(-65529など)