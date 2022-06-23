Exploiting RWX stack
---
When the stack has the executable bit set, we can arbtrarily insert shellcode and execute it, which is much more convienient than ret2libc. Here's how to do it.

## Getting shellcode

You can find almost any shellcode you need [here](http://shell-storm.org/shellcode/).

For most binaries, we'll either be dealing with i386 (Intel x86) or AMD64 (Intel x86-64) architecture. It is important to use the correct shellcode for the correct arch. Run `pwn checksec` on the binary to get the arch of the binary.

Most of the time, you'd want a shellcode that executes `/bin/sh`, so here are shellcodes for both i386 and AMD64 :)

- i386

`b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'`

- AMD64

`b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'`

## But how do I execute it???

To execute it, you can simply overwrite the instruction pointer to point to your shellcode.

Sample payload:

`<shellcode><buffer to fill up (n bytes, n being (offset from start of input to instruction pointer - length of shellcode))><address of start of input>`

What this does is put the shellcode at the start of the input, then overwrite the instruction pointer to the address of the start of the input. This is asssuming you have the address of the input! PIE is your biggest enemy here, as the address will be dynamic.

## Leaking address

Since ASLR is usually enabled, the address of the stack will be randomized. 

One way we can mitigate this is via format strings (if such a vuln is given). Simply find the offset where your input starts, and add any padding necessary to jump to the start of your shellcode.
