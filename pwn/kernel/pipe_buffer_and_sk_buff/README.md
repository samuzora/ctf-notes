# `pipe_buffer`

- _page_: `kmalloc-cg-1k`
- _leak heap_: nil
- _leak kbase_: `pipe_buf_operations`
- _arbitrary read/write_: nil
- _ROP_: `pipe_buf_operations->release`

A `pipe_buffer` is a struct that manages the buffer space used to sync 2 file
descriptors together, unidirectionally.

## Struct definition

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

## Allocation

```c
#include <unistd.h>

size_t buf[0x100];
size_t pipe_buf_spray = 0x5000;
int pipe_buf_fds[pipe_buf_spray][2];
for (int i = 0; i < pipe_buf_spray; i++) {
    pipe(pipe_buf_fds[i]);
    // need to write to actually get fields filled in
    write(pipe_buf_fds[i][1], &buf[0], 0x8);
}
```

## Freeing

```c
for (int i = 0; i < pipe_buf_spray; i++) {
    close(pipe_buf_fds[i][0]);
    close(pipe_buf_fds[i][1]);
}
```

## Exploit techniques

### ROP

Assuming we already have a UAF over `kmalloc-cg-1k` we can use a struct, for
example `sk_buff`, to put user-controlled data at the `ops` field of the
`pipe_buffer`, faking a vtable which can then be used for ROP.

#### Attacking `pipe_buffer` with `sk_buff`

`sk_buff` is a struct that manages an underlying buffer for a pair of sockets.
Similar to pipes, this socket pair connects 2 file descriptors together, and
needs an underlying buffer to synchronize. However, unlike `pipe_buffer`, the
socket pair is bidirectional, which means data can be read from and written to
either end of the socket pair.

It is allocated using the `socketpair` syscall, which has a wrapper in glibc:

```c
size_t target_size = 1024;
char payload[target_size - 320];
int sk_socket[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket);
write(sk_socket[0], payload, sizeof(payload));
```

The underlying `sk_buff` struct is as such:

```c
struct sk_buff {
    /* lots of irrelevant headers */

	/* These elements must be at the end, see alloc_skb() for details.  */
	sk_buff_data_t		tail;
	sk_buff_data_t		end;
	unsigned char		*head,
				*data;
	unsigned int		truesize;
	refcount_t		users;

#ifdef CONFIG_SKB_EXTENSIONS
	/* only useable after checking ->active_extensions != 0 */
	struct skb_ext		*extensions;
#endif
};
```

The actual struct that we're using for the exploit is `sk_buff.head`, which is
allocated along this path only at the point of writing to the socket:

```
unix_dgram_sendmsg -> sock_alloc_send_pskb -> alloc_skb_with_frags ->
alloc_skb -> __alloc_skb -> __kmalloc_reserve -> __kmalloc_node_track_caller ->
slab_alloc_node
```

with the second argument of `sock_alloc_send_pskb` eventually being the size of
the node allocated:

```c
	if (len > sk->sk_sndbuf - 32)
		goto out;

	if (len > SKB_MAX_ALLOC) {
		data_len = min_t(size_t,
				 len - SKB_MAX_ALLOC,
				 MAX_SKB_FRAGS * PAGE_SIZE);
		data_len = PAGE_ALIGN(data_len);

		BUILD_BUG_ON(SKB_MAX_ALLOC < PAGE_SIZE);
	}

	skb = sock_alloc_send_pskb(sk, len - data_len, data_len,
				   msg->msg_flags & MSG_DONTWAIT, &err,
				   PAGE_ALLOC_COSTLY_ORDER);
```

As the snippet above suggests, the allocated node is usually the length of the
data that we pass in, unless len is greater than `SKB_MAX_ALLOC`.

### Pagejacking

The `struct page` pointer points to a structure that manages physical-to-virtual
memory mappings, and each of these `struct page` is 0x40 bytes. More
importantly, if we can get 2 `pipe_bufs` to point to the same `struct page`,
then we will have a page-level UAF - and we'll have full control over the entire
page! We can then attack objects that require page allocations, such as slabs
passed to caches from the SLUB allocator, including specific caches like the
`filp` cache. We can then overwrite the permissions of important files such as
`/etc/passwd`.
