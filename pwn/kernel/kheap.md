# What are pages?

## `GFP_KERNEL` vs `GFP_KERNEL_ACCOUNT`

`GFP_KERNEL` will allocate chunks in `kmalloc-x` pages, while
`GFP_KERNEL_ACCOUNT` will allocate in `kmalloc-cg-x` pages.

## Cross-cache attack

When we want to leverage UAF to attack the kernel, sometimes we find ourselves
in the wrong page, and we want to change our UAF to another cache to continue
the exploit.

Each page in the kernel heap can store up to 16 chunks. When all the chunks in a
page are freed, the entire page itself will be freed by the buddy allocator.

This is usually done through a heap spray technique:

- Spray the heap to fill up our initial starting cache
- Free all the objects in the cache, including our UAF object (after this, it
  may help to wait a little so the kernel actually frees our page)
- Spray the heap with our target object and hope that the kernel allocates it
  onto the UAF object
