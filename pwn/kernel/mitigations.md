# SMAP

Prevents kernel to userspace page read access

# SMEP

Prevents kernel to userspace instruction execution

Prevents the use of our own shellcode/function, must use kROP (need to stack pivot)

Stack pivot can be done by controlling `rsp`, find appropriate gadgets in kernel and for specific challenge context

# KPTI

Must use `swapgs` and `iretq` to switch contexts

`swapgs`: can be found using `objdump -d vmlinux | grep swapgs`, then search through for `swapgs ; ret` instruction

`iretq`: same way and look for `iretq ; ret` instruction

Example (after getting correct creds):

```c
rop_chain[off++] = swapgs;
rop_chain[off++] = iretq;
rop_chain[off++] = get_shell;
rop_chain[off++] = user_cs;
rop_chain[off++] = user_rflags;
rop_chain[off++] = user_sp;
rop_chain[off++] = user_ss;
```

# CONFIG_SLAB_VIRTUAL

If this config option is enabled, the same virtual address used for a certain
cache will not be used for another type of cache, which effectively kills
any possibility for any sort of cross-cache attack.
