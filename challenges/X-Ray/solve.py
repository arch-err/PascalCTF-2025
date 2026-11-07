#!/usr/bin/env python

key = b"*7^tVr4FZ#7S4RFNd2"
encrypted = b"xR\bG$G\a\x19kPhgCa5~\t\x01"

decrypted = ""

for i in range(len(encrypted)):
    decrypted += chr(encrypted[i] ^ key[i])

print(decrypted)
