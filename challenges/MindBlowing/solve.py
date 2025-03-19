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

def extract_flag_in_halves():
    # Define the range of bits for the first and second halves
    lower_half_range = range(160)  # Bits 0–159
    upper_half_range = range(160, 320)  # Bits 160–319

    # Function to extract a specific range of bits
    def extract_bits(bit_range):
        seeds = [(1 << i) for i in bit_range]  # Generate seeds for the given range
        results = generate(seeds, idx=2)  # Call generate with the seeds
        extracted_int = 0
        for i, result in zip(bit_range, results):
            if result != 0:  # If the AND operation returned a non-zero value, the bit is 1
                extracted_int |= (1 << i)
        return extracted_int

    # Extract the lower and upper halves
    lower_half = extract_bits(lower_half_range)
    upper_half = extract_bits(upper_half_range)

    # Combine the two halves into a single integer
    full_flag_int = (upper_half << 160) | lower_half

    # Convert the integer back to bytes
    flag_bytes = full_flag_int.to_bytes((full_flag_int.bit_length() + 7) // 8, "big")

    # Decode the bytes to get the flag
    return flag_bytes.decode()



p = remote("mindblowing.challs.pascalctf.it", 420)
print(extract_flag())
p.close()

print(p.recvall(timeout=0.1).decode())
p.interactive()


# ---

# import signal, os

# SENTENCES = [
#     b"Elia recently passed away, how will we be able to live without a sysadmin?!!?",
#     os.urandom(42),
#     os.getenv("FLAG", "pascalCTF(REDACTEdblabl_1_sh0uld_ch3ck_th3_t0t4l_numb3r_0f_ONES}").encode(),
# ]


# def generate(seeds: list[int], idx: int) -> list[int]:
#     result = []
#     if idx < 0 or idx > 2:
#         return result
#     encoded = int.from_bytes(SENTENCES[idx], "big")
#     # print(int(encoded))
#     for bet in seeds:
#         # why you're using 1s when 0s exist
#         # print(bet)
#         # print(bet.bit_count())
#         if bet.bit_count() > 40:
#             continue
#         result.append(encoded & bet)

#     return result


# print(extract_flag())
