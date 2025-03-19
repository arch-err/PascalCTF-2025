#!/usr/bin/env python
#!CMD: ./solve.py
import re
from Crypto.Util.number import inverse, long_to_bytes
from sympy import factorint

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


def factorize_n(n):
    """
    Attempt to factorize n using sympy's factorint or other methods.
    """
    factors = factorint(n)  # Returns a dictionary {p: exponent}
    if len(factors) == 2:  # Ensure n is factored into two primes
        p, q = list(factors.keys())
        return p, q
    else:
        raise ValueError("Failed to factorize n")


def decrypt_ciphertexts(n, e, ciphertexts):
    """
    Decrypt ciphertexts using RSA private key.
    """
    # Factorize n to get p and q
    p, q = factorize_n(n)

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
        alice_plaintexts = decrypt_ciphertexts(alice_n, e, alice_ciphertexts)
        print("[+] Alice's plaintexts:")
        for pt in alice_plaintexts:
            print(pt)
    except ValueError as ve:
        print(f"[-] Failed to factorize Alice's n: {ve}")

    # Attempt to decrypt Bob's ciphertexts
    print("[+] Decrypting Bob's ciphertexts...")
    try:
        bob_plaintexts = decrypt_ciphertexts(bob_n, e, bob_ciphertexts)
        print("[+] Bob's plaintexts:")
        for pt in bob_plaintexts:
            print(pt)
    except ValueError as ve:
        print(f"[-] Failed to factorize Bob's n: {ve}")


if __name__ == "__main__":
    main()
