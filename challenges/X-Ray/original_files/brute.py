#!/usr/bin/env python

import subprocess
import itertools

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

i = 0

for combination in itertools.product(charset, repeat=9):
    i += 1
    # Join the tuple into a string
    data = "".join(combination)

    # Check if the generated string matches the target
    flag = "pascalCTF{" + data + "}"

    if i % 100 == 0:
        print(f"[*] Guessing with the flag '{flag}'...")

    out = subprocess.getoutput(f"echo {flag} | ./x-ray")
    if not out.endswith("wrong!"):
        print(out)
        break

data = "dd"
switcheroo
