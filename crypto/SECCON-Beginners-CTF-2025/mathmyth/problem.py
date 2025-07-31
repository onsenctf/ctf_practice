from Crypto.Util.number import getPrime, isPrime, bytes_to_long
import os, hashlib, secrets


def next_prime(n: int) -> int:
    n += 1
    while not isPrime(n):
        n += 1
    return n


def g(q: int, salt: int) -> int:
    q_bytes = q.to_bytes((q.bit_length() + 7) // 8, "big")
    salt_bytes = salt.to_bytes(16, "big")
    h = hashlib.sha512(q_bytes + salt_bytes).digest()
    return int.from_bytes(h, "big")


BITS_q = 280
salt = secrets.randbits(128)

r = 1
for _ in range(4):
    r *= getPrime(56)

for attempt in range(1000):
    q = getPrime(BITS_q)
    cand = q * q * next_prime(r) + g(q, salt) * r
    if isPrime(cand):
        p = cand
        break
else:
    raise RuntimeError("Failed to find suitable prime p")

n = p * q
e = 0x10001
d = pow(e, -1, (p - 1) * (q - 1))

flag = os.getenv("FLAG", "ctf4b{dummy_flag}").encode()
c = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"r = {r}")
