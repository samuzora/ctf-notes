# FUSE filesystem

Filesystem in UserSpacE (FUSE) is an interface for userland programs to create
their own handlers for filesystems, without having to create kernel modules.
This means we can handle reads, writes etc, which even allows a userland program
to lock a kernel thread when it copies from the user-defined filesystem into the
kernel.

## Compiling FUSE

The following is for libfuse3, not libfuse.

To compile your exploit, you might want to manually compile the FUSE shared
library to optimize for minimum size, so your exploit won't be too large.

Download the latest release from <https://github.com/libfuse/libfuse/releases>
and extract it. Follow the install instructions, and configure the following
compile options:

```bash
meson configure \
    -D debug=false \
    -D default_library=static \
    -D default_both_libraries=static \
    -D strip=true \
    -D optimization=s \
    -D enable_io_uring=false
```

Note: since it's compiled with gcc, you'll have to compile your exploit with gcc
instead of musl-gcc too.

You can compile your exploit like this:

```bash
gcc -o exploit -static -pthread ./demo.c `pkg-config fuse3 --cflags --libs` -Os
```
