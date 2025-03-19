#!/usr/bin/env python

from pwn import *

p = remote("morrisworm.challs.pascalctf.it", 1337)

p.interactive()
