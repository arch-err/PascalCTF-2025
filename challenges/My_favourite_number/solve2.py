#!/usr/bin/env python
#!CMD: ./solve2.py
import re
from Crypto.Util.number import inverse, long_to_bytes
from sympy import isprime
from concurrent.futures import ThreadPoolExecutor
import math
from math import isqrt  # Use integer square root for large numbers


def parse_output(file_path):
    """
    Parse the output.txt file to extract RSA parameters and ciphertexts.
    """
    with open(file_path, "r") as f:
        data = f.read()

    # Extract Alice's and Bob's RSA parameters
    alice_n = int(re.search(r"hi, i'm Alice, my public parameters are:\nn=(\d+)", data).group(1))
    bob_n = int(re.search(r"hi Alice! i'm Bob, my public parameters are:\nn=(\d+)", data).group(1))
    e = int(re.search(r"e=(\d+)", data).group(1))

    # Extract ciphertexts
    alice_ciphertexts = [int(x) for x in re.findall(r"alice: (\d+)", data)]
    bob_ciphertexts = [int(x) for x in re.findall(r"bob: (\d+)", data)]

    return alice_n, bob_n, e, alice_ciphertexts, bob_ciphertexts


def trial_division(n, start, end):
    """
    Attempt to find a factor of n using trial division in the range [start, end).
    """
    for i in range(start, end):
        if n % i == 0:
            return i
    return None



def parallel_factorize(n, num_threads=8):
    """
    Factorize n using multithreading and trial division.
    """
    # Define the range of numbers to test for factors
    sqrt_n = isqrt(n) + 1  # Use integer square root
    step = sqrt_n // num_threads

    # Create thread pool
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for i in range(2, sqrt_n, step):
            futures.append(executor.submit(trial_division, n, i, min(i + step, sqrt_n)))

        # Check results as they complete
        for future in futures:
            factor = future.result()
            if factor:
                return factor, n // factor

    return None, None


def decrypt_ciphertexts(n, e, ciphertexts, num_threads=8):
    """
    Decrypt ciphertexts using RSA private key.
    """
    # Factorize n to get p and q
    print(f"[+] Attempting to factorize n: {n}")
    p, q = parallel_factorize(n, num_threads=num_threads)
    if not p or not q:
        raise ValueError("Failed to factorize n")

    print(f"[+] Successfully factorized n: p = {p}, q = {q}")

    # Compute private key
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    # Decrypt each ciphertext
    plaintexts = []
    for c in ciphertexts:
        m = pow(c, d, n)  # RSA decryption
        plaintexts.append(long_to_bytes(m).decode("utf-8", errors="ignore"))

    return plaintexts


def main():
    # Parse the output.txt file
    alice_n, bob_n, e, alice_ciphertexts, bob_ciphertexts = parse_output("./original_files/output.txt")

    print("[+] Alice's RSA parameters:")
    print(f"n = {alice_n}")
    print(f"e = {e}")

    print("[+] Bob's RSA parameters:")
    print(f"n = {bob_n}")
    print(f"e = {e}")

    # Attempt to decrypt Alice's ciphertexts
    print("[+] Decrypting Alice's ciphertexts...")
    try:
        alice_plaintexts = decrypt_ciphertexts(alice_n, e, alice_ciphertexts, num_threads=8)
        print("[+] Alice's plaintexts:")
        for pt in alice_plaintexts:
            print(pt)
    except ValueError as ve:
        print(f"[-] Failed to factorize Alice's n: {ve}")

    # Attempt to decrypt Bob's ciphertexts
    print("[+] Decrypting Bob's ciphertexts...")
    try:
        bob_plaintexts = decrypt_ciphertexts(bob_n, e, bob_ciphertexts, num_threads=8)
        print("[+] Bob's plaintexts:")
        for pt in bob_plaintexts:
            print(pt)
    except ValueError as ve:
        print(f"[-] Failed to factorize Bob's n: {ve}")


if __name__ == "__main__":
    main()
