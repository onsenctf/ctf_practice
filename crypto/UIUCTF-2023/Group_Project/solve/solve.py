from Crypto.Cipher import AES
from Crypto.Util.number import *
from hashlib import *

c = 31383420538805400549021388790532797474095834602121474716358265812491198185235485912863164473747446452579209175051706
cipher = AES.new(md5(long_to_bytes(1)).digest(), AES.MODE_ECB)
print(cipher.decrypt(long_to_bytes(c)).decode())
