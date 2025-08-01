from pwn import *; context.log_level = 'WARNING'
from gmpy2 import *

q = [
    b"16, 111, 32, 95, 30, 97, 53, 74, 12, 115, 20, 107, 28, 99, 36, 91, 44, 83, 62, 65",
    b"6, 121, 61, 66, 13, 114, 38, 89, 47, 80, 21, 106, 58, 69, 24, 103, 18, 109, 31, 96",
    b"57, 70, 29, 98, 35, 92, 50, 77, 27, 100, 37, 90, 22, 105, 19, 108, 49, 78, 45, 82",
    b"54, 73, 1, 126, 2, 125, 3, 124, 34, 93, 4, 123, 48, 79, 23, 104, 5, 122, 41, 86",
    b"63, 64, 17, 110, 52, 75, 26, 101, 60, 67, 7, 120, 59, 68, 51, 76, 8, 119, 14, 113",
    b"43, 84, 33, 94, 40, 87, 9, 118, 46, 81, 56, 71, 15, 112, 10, 117, 55, 72, 42, 85",
    b"25, 102, 11, 116, 39, 88, 0",
]

stri = ""
while 'CCTF' not in stri:
    r = remote('01.cr.yp.toc.tf', 11337)
    r.recvline()
    r.recvline()
    r.recvline()

    # K
    in_K = []

    for i in range(6):
        # クエリを入力し受信データを整数リスト化する
        r.sendline(q[i])
        r.recvuntil(b'DID = ')
        rcv = r.recvline().strip().decode()
        res_nums = list(map(int, rcv.strip('[]').split(','))) if rcv != '[]' else []

        # 送信したデータを整数リスト化
        req_nums = list(map(int, q[i].decode().strip('[]').split(',')))
        print(f"{req_nums = }")
        print(f"{res_nums = }")


        # 受け取ったデータに対し、req_nums[2*i]^2 mod 127, .. + 1 を満たす要素の個数
        # req_nums[2*i]の2乗か2乗+1 が含まれているなら保留して次のクエリとする。
        next_req_nums = []

        for i in range(len(req_nums)//2):

            if len(list(filter(lambda res: res == pow(req_nums[2*i],2,127) or res == pow(req_nums[2*i],2,127)+1, res_nums))) <= 1:
            # if (pow(req_nums[2*i],2,127) in res_nums) or (pow(req_nums[2*i],2,127)+1 in res_nums):
                next_req_nums.append(req_nums[2*i])
        print(f"{next_req_nums = }")

        # クエリを入力し受信データを整数リスト化する
        if next_req_nums == []: continue
        r.sendline(str(next_req_nums).strip('[]').encode()+b','+q[6])
        r.recvuntil(b'DID = ')
        rcv = r.recvline().strip().decode()
        res_nums = list(map(int, rcv.strip('[]').split(','))) if rcv != '[]' else []

        # K の元を特定する：
        # 2回目のクエリ時にA-K に含まれているなら、Kにはその相方が含まれていたことになる
        for next_req_num in next_req_nums:
            if pow(next_req_num,2,127) in res_nums or pow(next_req_num,2,127) + 1 in res_nums:
                in_K.append(127 - next_req_num)
            else:
                in_K.append(next_req_num)
   

    print(f"{in_K = }")
    r.sendline(','.join(map(str, list(in_K))).encode())
    stri = r.recvline().decode()
    stri = r.recvline().decode()
    print(stri)
    r.close()
    print(len(in_K))





























# stri = ""
# while "CCTF" not in stri: 
#     K = set([i for i in range(127)])
#     # print(K)

#     r = remote('00.cr.yp.toc.tf', 11337)
#     r.recvline()
#     r.recvline()
#     r.recvline()

#     for i in range(9):
#         r.sendline(q[i])
#         r.recvuntil(b'DID = ')
#         req_nums   = list(map(int, q[i].decode().strip('[]').split(',')))

        
#         rcv = r.recvline().strip().decode()
#         res_nums = list(map(int, rcv.strip('[]').split(','))) if rcv != '[]' else []

#         acc = []
#         for n in req_nums:
#             if (pow(n,2,127) in res_nums) or ((pow(n,2,127)+1) in res_nums):
#                 acc.append(n)
#         K -= set(acc)
#         # print(acc)

#         # print(nums)
#         # a = list(map(lambda n: int(iroot(n,2)[0]), nums))
#         # print(a)
#         # K -= a
#     # for i in range(3):
#         # 

#     r.sendline(','.join(map(str, list(K))).encode())
#     stri = r.recvline().decode()
#     print(stri)
#     r.close()
#     print(len(K))