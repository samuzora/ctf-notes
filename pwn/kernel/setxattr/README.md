# setxattr

<https://elixir.bootlin.com/linux/v6.15.8/source/fs/xattr.c#L679>

Allocated at <https://elixir.bootlin.com/linux/v6.15.8/source/fs/xattr.c#L619>

Freed in the same path at
<https://elixir.bootlin.com/linux/v6.15.8/source/fs/xattr.c#L715>

A very useful struct for spraying, since we have full control over the contents
of the struct, and it has dynamic size in non-accounted kmalloc caches (non-cg
cache)

Must be used in conjunction with userfaultfd or FUSE (or any other mechanism
that allows us to pause the kernel thread during reading or file access) because
it's freed in the same path as allocation.

## userfaultfd

Spraying with userfaultfd is quite noisy since we must mmap a new page for every
setxattr we wish to spray.

There might be a clever way to use minor page faults and
`UFFDIO_REGISTER_MODE_MINOR` in v5.13 and above. 

> Minor fault mode supports only hugetlbfs-backed (since Linux 5.13)
> and shmem-backed (since Linux 5.14) memory.

More info here: <https://man7.org/linux/man-pages/man2/userfaultfd.2.html>

## FUSE
