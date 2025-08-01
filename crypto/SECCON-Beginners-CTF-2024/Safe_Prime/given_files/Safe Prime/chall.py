import os
from Crypto.Util.number import getPrime, isPrime

FLAG = os.getenv("FLAG", "ctf4b{*** REDACTED ***}").encode()
m = int.from_bytes(FLAG, 'big')

while True:
    p = getPrime(512)
    q = 2 * p + 1
    if isPrime(q):
        break

n = p * q
e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")
