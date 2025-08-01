from itertools import cycle

cphr = "POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9"
s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"

k = "".join([s[(s.find(c) - s.find(p)) % len(s)] for c, p in zip(cphr, "SECCON{")])
key = k + k[::-1]

print("".join([s[(s.find(c) - s.find(k)) % len(s)] for c, k in zip(cphr, cycle(key))]))
