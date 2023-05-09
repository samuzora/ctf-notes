# Format String

Format string vulns are a class of vulns that occur when untrusted input is passed directly into printf(). 
This not only occurs in arbitrary reading of values off the stack, but also 
arbitrary write using the %n specifier (write-what-where condition). 

## Arbitrary read
This attack is very simple, just write a short script to leak the first 500~ values off the stack 
using the %i$p specifier, where i is a number from 1-500. Certain values of note:

1. `0x8e918c891b347a00` 
	- Values that look like this are very likely the canary. They are usually longer than the rest of the leaks, and end with a null byte (\x00)
2. `0x4012ce`
	- In a non-PIE binary, these values are likely function addresses. This can be useful later on (leaking libc)
3. `0xff918d8e01929e01`
	- These are likely the stack (begins with \xff)
4. `0x41414141` or `0x70243625`
	- These values are your input, which we will call the offset

> Note that %0$p is not a valid format string.

Besides leaking pointers off the stack, we can also leak values off anywhere we want. 

The %s specifier returns a string at the address on the stack. 

This means that after finding our offset, we can simply move 1 up (to an empty offset), and put in the address of whatever we want to leak.

This includes GOT! This is an alternative way to leak LIBC addresses.

Arbitrary read is only useful if the flag has been read. Otherwise, we need something more potent!

---

## Arbitrary write
This attack is a bit more complicated, but can reward you with condition bypass or even a shell!

### The %n specifier
This specifier takes the number of bytes from the start of the format string to the specifier, and writes it into the address it's pointing at. 
In essence: `hello%n` will write 0x5 into the "address" that the first value on the stack is pointing to 
(if it doesn't point to a valid address, printf will crash). We can control this address though!

### Controlling the address
First, we need to determine our offset through arbitrary read. This offset will be the start of our string. 
If it isn't aligned to a particular offset, we can align it by adding the correct number of bytes to the start of our input. 
For example, if our input is AAAABBBB, and `%4$p` prints `0x42414141` and `%5$p` prints `0x00424242`, just shift the input by 1, ie. AAAAABBBB

We can then overwrite the GOT entry of a function called after `printf`, and change it to something else (address of main)

Candidate functions:
* `exit()`
* `__libc_fini_array()`
* `__stack_chk_fail()` (only if canary enabled)
* `puts()` (must be called explicitly)

> While a fmtstr2win only requires one leak, anything more advanced 
> (fmtstr2libc, canary/PIE bypass) requires more than 1 printf leak. 
> This is why we set the victim function to main, so we can continually
> exploit the printf vuln, and leak all the values we want.

### This sucks to do manually...
Of course, we can always use pwntools to help us construct the payload.

```py
writes={elf.got["exit"]: elf.symbols["main"]}
payload = fmtstr_payload(<offset>, writes=writes)
```

### Leaking canary/PIE/libc base/offset
You could manually calculate the offsets from the stack via GDB, or you could...

use ffuzzer!!

> ffuzzer - by samuzora
>
> This fuzzer allows you to fuzz format-string offsets to various leaks of interest, with a high success rate. 
> No scripting required - fully CLI-based!
> `pip install ffuzzer`
