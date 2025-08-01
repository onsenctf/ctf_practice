from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.number import *

exec(open('output.txt').read())

s = ((A * pow(1+A, -1, p)) % p
print(AES.new(md5(long_to_bytes(s)).digest(), AES.MODE_CBC, iv=int(ciphertext[:32],16).to_bytes(16,'big')).decrypt(int(ciphertext[32:], 16).to_bytes(32, 'big')))

# => b'FLAG{Do_the_math396691ba7d7270a}'
