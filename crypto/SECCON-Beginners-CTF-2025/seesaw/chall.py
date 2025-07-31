import os
from Crypto.Util.number import getPrime

FLAG = os.getenv("FLAG", "ctf4b{dummy_flag}").encode()
m = int.from_bytes(FLAG, 'big')

p = getPrime(512)   
q = getPrime(16)
n = p * q
e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")