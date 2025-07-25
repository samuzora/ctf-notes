# `sk_buff`

> _page_: `kmalloc-cg-1k`
> _leak heap: nil
> _leak kbase_: nil
> Arbitrary read/write: nil
> ROP: nil

`include/linux/skbuff.h`:

```c
struct sk_buff {
  // unimportant headers

  /* These elements must be at the end, see alloc_skb() for details.  */
  sk_buff_data_t    tail;
  sk_buff_data_t    end;
  unsigned char    *head, // this is what actually goes into kmalloc-cg-1k
        *data;
  unsigned int    truesize;
  refcount_t    users;
}

/*
 * &sk_buff.head points to the main "head" buffer. The head buffer is divided
 * into two parts:
 *
 *  - data buffer, containing headers and sometimes payload;
 *    this is the part of the skb operated on by the common helpers
 *    such as skb_put() or skb_pull();
 *  - shared info (struct skb_shared_info) which holds an array of pointers
 *    to read-only data in the (page, offset, length) format.
 */
```

Mostly good for exploiting a UAF over `pipe_buf` to get ROP. 

## Interacting with `sk_buff`

### Alloc

```c
size_t socket_num = 0x4;
size_t skbuff_num = 128;
size_t sk_sockets[socket_num][2];

for (int i = 0; i <= socket_num; i++) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_sockets[i])) {
        perror("socketpair");
        return 1;
    }
}

// create sk_buffs
for (int i = 0; i < socket_num; i++) {
    for (int j = 0; j < skbuff_num, j++) {
        write(sk_sockets[i][0], paylload, 1024 - 320)
    }
}
```
