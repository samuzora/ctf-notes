# FILE struct exploitation

## Fields

```c
file = {
  _flags = -72540026,
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x0,
  _IO_read_base = 0x0,
  _IO_write_base = 0x0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x0,
  _IO_buf_end = 0x0,
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _markers = 0x0,
  _chain = 0x7ffff7fb4780 <_IO_2_1_stdout_>,
  _fileno = 2,
  _flags2 = 0,
  _old_offset = -1,
  _cur_column = 0,
  _vtable_offset = 0 '\000',
  _shortbuf = "",
  _lock = 0x7ffff7fb58c0 <_IO_stdfile_2_lock>,
  _offset = -1,
  _codecvt = 0x0,
  _wide_data = 0x7ffff7fb38a0 <_IO_wide_data_2>,
  _freeres_list = 0x0,
  _freeres_buf = 0x0,
  __pad5 = 0,
  _mode = 0,
  _unused2 = '\000' <repeats 19 times>
},
vtable = 0x7ffff7f52430 <_IO_file_jumps>
```

## Flags specification

```c
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```

## Arb read

Upgrade limited write primitive to arbitrary read

Works on any open file, `stdout` is the easiest

When using on `stdout`, triggered on writing funcs (`puts`, `printf` etc)

### Call chain example (puts)

```
puts(str)
-> _IO_new_file_xsputn (stdout, str, len)
    -> _IO_new_file_overflow (stdout, EOF)
      -> new_do_write(stdout, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)
          -> IO_new_file_write(stdout, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)
              -> write(stdout->fileno, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)
```

---

### Requirements

- `flags = flags & ~_IO_NO_WRITES | _IO_CURRENTLY_PUTTING`
- `fileno = 1 (stdout)`
- `_IO_write_base = <target>`
- `_IO_write_ptr = <target> + len`
- `_IO_write_end = <target> + len` (may be required if program is crashing)
- `_IO_read_end = <target>` (to prevent adjusting of stream buffer as shown
below)

```c
// in new_do_write
_IO_size_t count;
if (fp->_flags & _IO_IS_APPENDING) {
    // ...
} else if (fp->_IO_read_end != fp->_IO_write_base) { // skip this
    // ...
}
count = _IO_SYSWRITE(fp, data, to_do); // goal
```

## Arb write

Upgrade limited write primitive to arb write

Works on stdin, triggered by reading funcs (`gets`, `scanf`, `fgets` etc)

### Requirements

- `flags = flags & ~_IO_NO_READS`
- `_IO_read_base = 0x0`
- `_IO_read_ptr = 0x0`
- `_IO_buf_base = <target>`
- `_IO_buf_end = <target> + len`

Caveat: not sure if this works when buffering is turned off

---

- [https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique]
- [https://seb-sec.github.io/2020/04/29/file_exploitation.html]
- [https://chovid99.github.io/posts/stack-the-flags-ctf-2022/#getting-a-libc-leak]
