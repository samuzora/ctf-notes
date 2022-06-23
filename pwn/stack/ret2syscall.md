ret2syscall
---
ret2syscall refers to a collection of exploits that are similar to ret2libc, but do not take advantage of libc. Rather, all gadgets used in the ropchain come from the binary. This is especially useful for static build binaries, where all functions are contained in the executable, and no external libraries are dynamically loaded.

## Theory
ret2syscall depends on the binary having the `syscall` gadget. This gadget basically calls a function from the OS. From Wikipedia: 

> ... syscall is the programmatic way in which a computer program requests a service from the kernel of the operating system on which it is executed.

### How syscall works
`syscall` reads an integer from `$rax`. This integer specifies which service the program would like to call.

For **64-bit**, some services of interest are:

| ID ($rax) 	| Service or function 			|
| ------------- | ----------------------------- |
| 0 			| read(fd, buf, count) 			|
| 1				| write(fd, buf, count) 		|
| 2 			| open(path, flags)				|
| 59 			| **execve(path, args, env)**	|

The complete list of syscalls for x64 bit can be found here: <https://filippo.io/linux-syscall-table/>

TODO: 32-bit syscall

For **32-bit**, 

| ID ($eax) 	| Service 			  |
| ------------- | ------------------- |
| 11 			| execve			  |

Most of the time, we're interested in popping a shell, so ID 59 `execve` is very important, as it allows us to run *any* binary of our choice.

Parameters can also be passed into syscall in these registers, in sequence: 

`$rdi`, `$rsi`, `$rdx`, `$r10`, `$r8`, `$r9`

`execve` takes in 3 parameters: `execve(pathname, arguments, env\_vars)`. 

The pathname we want is, of course, `/bin/sh`. It's not a given that this string can be found in the binary though, so we might need to perform some ROP acrobatics. 

To find `/bin/sh`:
`ROPgadget --binary ./hackme --string '/bin/sh'`

If not found, we can do 1 of 2 things:
1. Insert our own `/bin/sh` into some empty section in memory, and point `$rdi` to whereever we put the string at
	- We cannot do this just by popping `/bin/sh` into `$rdi`, as `execve` will grab the string from the address that `$rdi` *points* to, not the value of `$rdi` itself.
	- Instead, we need to utilize gadgets such as `mov qword ptr [rax], rdx`, which will copy the contents of `$rdx` into the address pointed at by `$rax`. We can easily control this by manipulating gadgets.
2. Manually piece together the string `/bin/sh` char by char. TODO: find a writeup explaining this

When popping a shell, we definitely won't need any arguments or env vars. Since these arguments need to be arrays, if we were to put a value other than NULL, we'd have to manually construct our own arrays, which is very cumbersome. Thus, we can just set them to NULL to avoid any errors.

This portion is quite similar to one_gadgets. The registers of interest may not necessarily be NULL or 0, so we need to string some gadgets together to control them. 

After all registers have been settled, we can go ahead and call a gadget with `syscall`. This gadget doesn't need to have a `ret` instruction, as the syscall will be our last gadget in the ropchain.
