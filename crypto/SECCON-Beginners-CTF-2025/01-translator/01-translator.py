import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long


def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), 16))

flag = os.environ.get("FLAG", "CTF{dummy_flag}")
flag_bin = f"{bytes_to_long(flag.encode()):b}"
trans_0 = input("translations for 0> ")
trans_1 = input("translations for 1> ")
flag_translated = flag_bin.translate(str.maketrans({"0": trans_0, "1": trans_1}))
key = os.urandom(16)
print("ct:", encrypt(flag_translated, key).hex())
