# `pipe_buf` struct

> _page_: `kmalloc-cg-1k`
> _leak heap_: nil
> _leak kbase_: `pipe_buf_operations`
> _arbitrary read/write_: nil
> _ROP_: `pipe_buf_operations->release`

`include/linux/pipe_fs_i.h`:

```c
/**
 * struct pipe_buffer - a linux kernel pipe buffer
 * @page: the page containing the data for the pipe buffer
 * @offset: offset of data inside the @page
 * @len: length of data inside the @page
 * @ops: operations associated with this buffer. See @pipe_buf_operations.
 * @flags: pipe buffer flags. See above.
 * @private: private data owned by the ops.
 **/
struct pipe_buffer {
  struct page *page;
  unsigned int offset, len;
  const struct pipe_buf_operations *ops;
  unsigned int flags;
  unsigned long private;
};

struct pipe_buf_operations {
  int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
  /*
   * When the contents of this pipe buffer has been completely
   * consumed by a reader, ->release() is called.
   **/
  void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
  bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
  bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};
```


## Interacting with `pipe_buf`

### Alloc

```c
size_t buf[0x100];
size_t pipe_buf_spray = 0x5000;
int pipe_buf_fds[pipe_buf_spray][2];
for (int i = 0; i < pipe_buf_spray; i++) {
    pipe(pipe_buf_fds[i]);
    // need to write to actually get fields filled in
    write(pipe_buf_fds[i][1], &buf[0], 0x8);
}
```

### Free

```c
for (int i = 0; i < pipe_buf_spray; i++) {
    close(pipe_buf_fds[i][0]);
    close(pipe_buf_fds[i][1]);
}
```

# Examples

## ROP

Get `pipe_buf_operations` to point to our fake vtable, and construct a ROP chain
elsewhere to pivot to after `pipe_buf_operations->release`.

## Dynamics

### `sk_buff`

Works very well!

### `msg_msg` 

Also possible, but we can only control `pipe_buf_operations` via `msg_msg->mtype`, and we have no control over the other fields. Also, slub may error out due to detected double free.

## Pagejacking

TODO
