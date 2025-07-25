# House of Mind

House of Mind exploits non-main arena chunks.


> Requirements
> - Heap leak
> - Ability to allocate lots of chunks
> - Free chunks
> - Heap overflow (must overwrite flags in size)

> Primitive
> Write a freed chunk to arbitrary address

> Further vectors
> House of Apple: Overwrite `_chain` of `_IO_2_1_stdin_`
> Overwrite `global_max_fast`

## How it works

Non-main arena heaps don't have a special arena allocated in glibc. Instead, there is a `heap_info` struct stored at
the very top of the heap. The struct looks as such:

```c
int main() {
    print("a")
}
```

`mstate` is the arena for this heap. If we are able to control this, when freeing a chunk (especially in fastbin), the
freed chunk pointer will be placed at an offset from this arena (in the `fastbinsy` array).

To calculate the address of this `heap_info` struct:

```python
mmap_threshold = 0x20000 - 0x20
heap_max_size = 0x4000000
heap_info_addr = (heap_leak + heap_max_size) & ~(heap_max_size - 1)
```

So we need to allocate lots of chunks until `heap_info_addr` is within our heap memory. Then we can allocate a chunk to
fake this struct.

Subsequently, we need to exploit a heap overflow to change our victim chunk into a non-main arena chunk. Upon freeing
this chunk, a pointer to this chunk will be written to the corresponding `fastbin` array.

## Restrictions

The fake arena we want to write to has a small restriction that needs to be fulfilled. `system_mem` must be greater than
the size of the fastbin chunk we are freeing. So when choosing the target write:

- Target must be within fastbin array location of arena
- There must be a sufficiently large value at +0x888 (or somewhere there) to fulfill `system_mem`
