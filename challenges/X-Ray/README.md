# X-Ray
*I've recently written my first license checker, maybe Steam will buy it...*

## Solution
1. So, after poking around with various tools I set out to learn more about `radare2`. After learning a bit about the tool and looking around I found both an encrypted string and a key in the binary.
2. The code simply XORs every char in the input-value with every char in the key and checks if it's equal to the encrypted string. We can XOR-decrypt teh encrypted string with the key to get the right input, to get the flag:
3. `./solve.py`


## Flag
**Flag:** `pascalCTF{ReV3r53_1s_4w3s0m3}`
