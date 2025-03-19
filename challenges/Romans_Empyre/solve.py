#!/usr/bin/env python
import string

alphabet = string.ascii_letters + string.digits + "{}_-.,/%?$!@#"

with open("./original_files/output.txt", "r") as f:
    encrypted_flag = f.read()

# Just brute force the key
for key in range(1, len(alphabet)):
    decrypted_flag = ""

    for c in encrypted_flag:
        if c in alphabet:
            original_index = (alphabet.index(c) - key) % len(alphabet)
            decrypted_flag += alphabet[original_index]
        else:
            decrypted_flag += c

    if decrypted_flag.startswith("pascalCTF{") and decrypted_flag.endswith("}"):
        print(f"Decrypted FLAG: {decrypted_flag}")
        break
