---
title: "snake ctf 2024"
date: 2024-10-25T16:56:10+10:00
draft: false
toc: false
Summary: "Learning more about ROP Gadgets."
images:
tags:
  - ctf
  - pwn
---

### Pwny-trivia

This was a challenge that I was not able to complete in time but taught me a lot. I followed along with the offical solve to learn more and you can to here:

https://github.com/MadrHacks/snakeCTF2024-writeups/tree/main/pwn/pwny-trivia



We are given a binary that asks us to solve 5 quiz questions and upon doing so we can enter our details for a prize!.

```bash
Welcome to the Great Trivia Challenge!

You must give the right answer to 5 questions to win

For what purpose would you use an awl? (answer max 100 chars)

```


This was fun as I dumped all the question and answers with `strings` the hard part was yet to come. A syscall is then used to read in the users input.

The game plan for this challenge is to make a ROP chain, where we set up an exec syscall.

#### setting up syscall
So to solve this we need to prepare a few details for the syscall, we want to call execve with `/bin/bash`.


```
	execve	man/ cs/	0x3b	const char *filename	const char *const *argv	const char *const *envp
```

If we check the man pages for `execve`, we need to provide the path (or memory address) of what to execute and then an argv & envp.

```
       int execve(const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[]);
```

The objectives are as follows
- Pick a section of writeable memory to use to store `/bin/bash`
- Write `/bin/bash` to that memory location 
- Store this address in rbx
- Set rax 0x3b for the execve syscall type
- load arguments into correct registers (rdi, rsi, rdx)
- make syscall

The writeup gives a list of gadgets that we can use to do this.

```
ADD_RBX_1_MUL_RBX_MOV_RBX_RAX = 0x4011ca # add rbx, 1; mul rbx; mov rbx, rax; ret;
XOR_RBX_RBX = 0x4011dc # xor rbx, rbx; ret;
MOV_RCX_RBX = 0x4011e7 # mov [rcx], rbx;
POP_RCX_XOR_RAX_RCX_SUB_RAX_1 = 0x4011f2 # pop rcx; xor rax, rcx; sub rax, 0x1; ret
POP_RDI_POP_RSI_POP_RDX = 0x401202 # pop rdi; pop rsi; pop rdx; ret;
SYSCALL = 0x40152a # syscall
```

This was quite intimidating for me at first so I spent some time to try and better understand the mechanics of how this works.

#### A better understanding of ROP
A curious question I had was how do our addresses of choice get put onto the top of the stack when we have multiple gadgets and arguments?

After a little bit of reading its key to to understand that when return is called it additionally pops off the values at the `$RSP` pointer. This was a bit of a eurika moment for me as to do ROP programming.

Lets have a closer look at the solve payload to see this mechanic in action.

```python3

POP_RCX_XOR_RAX_RCX_SUB_RAX_1 = 0x4011f2 # pop rcx; xor rax, rcx; sub rax, 0x1; ret
POP_RCX_XOR_RAX_RCX_SUB_RAX_1 = 0x4011f2 # pop rcx; xor rax, rcx; sub rax, 0x1; ret

def write_bin_sh():
    chain = flat(
        # zeroing rax after last printf in program (prints 0x26 bytes)
        POP_RCX_XOR_RAX_RCX_SUB_RAX_1,
        0x27,
        # now rax = 0
        POP_RCX_XOR_RAX_RCX_SUB_RAX_1, b'0bin/sh\x00', # '0' gets decremented
    )

    return chain
```

<!-- ![stack](/images/snakectf/stack.PNG) -->
<img src="/images/snakectf/stack.PNG" alt="stack" class="img-medium">


So the red highlights show the inital buffer that we use for our input. This is after it has been over written, the highlight towards the bottom show the addresses of the gadgets and the the arguments for the gadget.

Lets step through and see this in action. 

<!-- ![before_leave](/images/snakectf/before_leave.PNG) -->
<img src="/images/snakectf/before_leave.PNG" alt="before" class="img-medium">

Currently we can see that the stack pointer still points to the local variables before we perform the `leave` instruction.

<!-- ![after_leave](/images/snakectf/after_leave.PNG) -->
<img src="/images/snakectf/after_leave.PNG" alt="after" class="img-medium">


After the leave call we can see that the local variables in that stack frame have been cleaned up. The stack pointer now points to what would be the return address but in our case the gadget.

The next part is important here when we watch the stack pointer and perform the next `ret` instruction. We can see that the instruction pointer will go to `4011f2` and will be popped off the stack.

<!-- ![after_ret](/images/snakectf/after_ret.PNG) -->
<img src="/images/snakectf/after_ret.PNG" alt="after_ret" class="img-medium">

Now that we have a greater understanding for this mechanic lets look at how we get to a shell.


### Back to it
I highly recommend the writeup as it provides better insight than I can but I will quote as to how the other gadgets are used in the payload to write in memory and call execve.


An arbitrary writable address can be chosen, for example 0x407b20 which is in BSS, and loaded into rcx by using `POP_RCX_XOR_RAX_RCX_SUB_RAX_1`. At this point `MOV_RCX_RBX = mov [rcx]`, rbx writes `/bin/sh\x00` in memory.

The last step needed is loading `0x3b` in rax in order to perform a execve. If the binary is debugged in gdb it can be seen that after the execution of the chain until this point, rax contains the value `0x68732f6e291f3a`, so by sending `0x68732f6e291f3a ^ (0x3b + 1)` as a payload (+1 because the gadget contains sub rax 1) it is possible to store the correct value in rax. With `POP_RDI_POP_RSI_POP_RDX` the registers used to store the arguments can be modified, and finally with `SYSCALL` a shell gets spawned.