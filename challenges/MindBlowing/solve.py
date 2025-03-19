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
    # Generate seeds to isolate each bit position (up to 320 bits, assuming the flag is 40 bytes)
    seeds = [(1 << i) for i in range(520)]  # 40 bytes * 8 bits = 320 bits

    # Call the generate function with idx = 2 (the flag)
    results = generate(seeds, idx=2)
    # print(results)

    # Reconstruct the integer representation of the flag
    flag_int = 0
    for i, result in enumerate(results):
        if result != 0:  # If the AND operation returned a non-zero value, the bit is 1
            flag_int |= (1 << i)

    # Convert the integer back to bytes
    flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "big")

    # Decode the bytes to get the flag
    return flag_bytes.decode()



p = remote("mindblowing.challs.pascalctf.it", 420)
print(extract_flag())
p.close()

