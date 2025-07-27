# userfaultfd

By triggering a pagefault on a userfaultfd-registered region of memory, we can
cause locks even in the kernel, allowing us to do other things while the kernel
has to wait for us to release the lock.

Refer to `demo.c` for an example.

## setxattr

Since setxattr is allocated and freed on the same path, it should be impossible
to use this object for a spray. However, if we get it to copy from a
userfaultfd-registered region of memory, the kernel thread will lock after
allocation but before freeing, allowing us to use this struct for spray. And
it's a very useful struct for spraying because it has dynamic size in
non-accounted caches (not `cg`), and has full control over the entire region of
memory allocated to it.

## Mitigations

If `CONFIG_USERFAULTFD` is disabled, or `vm.unprivileged_userfaultfd = 0`, this
method cannot be used.

`CONFIG_HIGHMEM` might have an effect on this particular demo, because it relies
on the kernel not allocating a physical page to our `mmap`. However, if
`CONFIG_HIGHMEM=n`, there is no `struct page` that is allocated without a
physical page backing it. (should test this out)
