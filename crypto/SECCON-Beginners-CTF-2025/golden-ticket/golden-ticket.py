import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


flag = os.environ.get("FLAG", "ctf4b{dummy_flag}")
iv = os.urandom(16)
key = os.urandom(16)
challenge = os.urandom(16 * 6)
ENC_TICKET = 3
DEC_TICKET = 3
GOLDEN_TICKET = 0

print('start!: ', challenge.hex())

def menu() -> int:
    print("Your tickets:")
    if ENC_TICKET > 0:
        print(f"{ENC_TICKET} encryption ticket(s)")
    if DEC_TICKET > 0:
        print(f"{DEC_TICKET} decryption ticket(s)")
    if GOLDEN_TICKET > 0:
        print(f"{GOLDEN_TICKET} golden ticket(s)")
    print()
    print(f"1. Encrypt")
    print(f"2. Decrypt")
    print(f"3. Get ticket")
    print(f"4. Get flag")
    print(f"5. Quit")
    while True:
        i = int(input("> "))
        if 1 <= i <= 5:
            return i
        print("Invalid input!")

def consume_ticket(enc: int = 0, dec: int = 0, golden: int = 0):
    global ENC_TICKET, DEC_TICKET, GOLDEN_TICKET
    if ENC_TICKET < enc or DEC_TICKET < dec or GOLDEN_TICKET < golden:
        print("Not enough tickets.")
        exit(1)
    ENC_TICKET -= enc
    DEC_TICKET -= dec
    GOLDEN_TICKET -= golden

while True:
    i = menu()

    if i == 1:
        consume_ticket(enc=1)
        pt = bytes.fromhex(input("pt> "))
        if len(pt) > 16:
            print("Input must not be longer than 16 bytes.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        print(f"ct:", cipher.encrypt(pad(pt, 16)).hex())

    if i == 2:
        consume_ticket(dec=1)
        ct = bytes.fromhex(input("ct> "))
        if len(ct) > 16:
            print("Input must not be longer than 16 bytes.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        print("pt:", cipher.decrypt(pad(ct, 16)).hex())

    if i == 3:
        print("challenge:", challenge.hex())
        answer = bytes.fromhex(input("answer> "))
        if len(answer) != len(challenge) + 16:
            print("Wrong length.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=answer[:16])
        print('answer: ', cipher.decrypt(answer[16:]).hex())
        if cipher.decrypt(answer[16:]) == challenge:
            print("Correct!")
            GOLDEN_TICKET += 1337
        else:
            print("Wrong :(")

    if i == 4:
        consume_ticket(golden=1)
        print("flag:", flag)

    if i == 5:
        print("Bye!")
        exit(0)
