---
title: "babyarx"
date: 2022-10-25T16:56:10+10:00
draft: false
toc: false
Summary: "Cryptography challenge from ductf2022"
images:
tags:
  - crypto
  - ctf
---

For this challenge we are given a .py file and the resulting hash.

``` python
class baby_arx():
    def __init__(self, key):
        assert len(key) == 64
        self.state = list(key)

    def b(self):
        b1 = self.state[0]
        b2 = self.state[1]
        b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
        b2 = (b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff
        b = (b1 + b2) % 256
        self.state = self.state[1:] + [b]
        return b

    def stream(self, n):
        return bytes([self.b() for _ in range(n)])


FLAG = open('./flag.txt', 'rb').read().strip()
cipher = baby_arx(FLAG)
out = cipher.stream(64).hex()
print(out)

# cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b
```

Just from the source code we can see that the flag length is 64. The cipher takes the current bytes and performs and, rotate, xor. Then adds this with the next byte to get the cipher text.

The cipher uses the next letter and the current to generate the cipher text. This means if we know the current letter and the cipher text we can brute force what the next character is.

``` python
def solve_next_letter(current_character, current_ct):
    byte_one = b1_hashes[current_character]
    #brute force other hash
    for c in string.printable:
        byte_two = b2_hashes[c]
        if (byte_one + byte_two) % 256 == current_ct:
            return c
```
Code is needed to then keep track of ingesting the hash and turning it into byte sections.

``` python
CT = "cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b"
CT_BYTES=[]
for x in range(0, len(CT),2):
    CT_BYTES.append(CT[x:x+2])
```

We then create a hash map of all the possible hashes given the two ARX operations.

``` python
#calculate all hashes
for c in string.printable:
    print(c)
    char_code = ord(c)
    print(f'char code {char_code} c: {c}')
    b1_hashes[c] = (char_code ^ ((char_code << 1) | (char_code & 1))) & 0xff
    b2_hashes[c] = (char_code ^ ((char_code >> 5) | (char_code << 3))) & 0xff
```
We know that a flag starts with "DUCTF{ so we can use that to kick off solving the cipher text. Putting it all together results in the following code.

``` python
#!/usr/bin/python3
import string

CT = "cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b"
CT_BYTES=[]
for x in range(0, len(CT),2):
    CT_BYTES.append(CT[x:x+2])

b1_hashes = {}
b2_hashes = {}

#calculate all hashes
for c in string.printable:
    print(c)
    char_code = ord(c)
    print(f'char code {char_code} c: {c}')
    b1_hashes[c] = (char_code ^ ((char_code << 1) | (char_code & 1))) & 0xff
    b2_hashes[c] = (char_code ^ ((char_code >> 5) | (char_code << 3))) & 0xff

flag="DUCTF{"
#cut the first 5 bytes
CT_BYTES = CT_BYTES[5:]

def solve_next_letter(current_character, current_ct):
    print(f"looking up {current_character}")
    byte_one = b1_hashes[current_character]
    #brute force other hash
    for c in string.printable:
        byte_two = b2_hashes[c]
        if (byte_one + byte_two) % 256 == current_ct:
            return c


while len(CT_BYTES):
    #we know what the current CT and PT
    current_letter = flag[-1:]
    current_ct = int(CT_BYTES[0],16)

    next_letter = solve_next_letter(current_letter,current_ct)
    flag += str(next_letter)
    CT_BYTES.pop(0)

print(flag)
```