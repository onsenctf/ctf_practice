# Rotated Secret Analysis
`chall.py`, `output.txt`が与えられている．

## 解答
- 簡単な換字暗号である．鍵のアルファベットの番数分，平文をずらしている．
- `chall.py`内の`result += LOWER_ALPHABET[(LOWER_ALPHABET.index(secret[i]) + LOWER_ALPHABET.index(key[i])) % 26]`の`+`を`-`に変えれば，暗号化関数`encrypt`がそのまま復号関数になる．
- あとは`echo 'RpgSyk{qsvop_dcr_wmc_rj_rgfxsime!}' | python3 solve.py | grep RicSec`等とすればフラグが得られる