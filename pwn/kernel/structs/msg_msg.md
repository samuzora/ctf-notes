# `msg_msg` struct

> _page_: `kmalloc-cg-64` to `kmalloc-cg-4k` (higher pages will be allocated
> using mmap)
> _leak heap_: `fd` and `bk` pointers of heap chunks can be leaked (very useful!)
> _leak kbase_: ?
> _arbitary read/write_: `msgmsg_seg` + race condition (`msgmsg_seg` pointer to be
> overwritten during `msgsnd`)
> _ROP_: nil

`include/linux/msg.h`:

```c
struct msg_msg {
  struct list_head m_list;
  long m_type;
  size_t m_ts;    /* message text size */
  struct msg_msgseg *next;
  void *security;
  /* the actual message follows immediately */
};

struct list_head {
  struct list_head *next, *prev;
};
```
 
Every `msg_msg` exists in a queue, where each queue is of a different size. The
queue is doubly-linked and `msg_msg` can be specifically freed by `mtype`
identifier.

This struct is useful for cross-cache (due to its flexibility in different
caches), you usually want to use this to transition between different cache
sizes

## Interacting with `msg_msg`

First, we should create a template `msgmsg_256` that we will use for our
allocated `msg_msg`:

```c
struct msgmsg_256 {
    long mtype;
    char mtext[256 - 0x30];
} msgmsg_256;
msgmsg_256.mtype = 0x256;
```

Queues must also first be initialized:

```c
#include <sys/msg.h>
// if spray is too small, our target page won't be overwritten
size_t msgs_spray = 0x5000; 
size_t msg_queues[msgs_spray];
for (int i = 0; i < msgs_spray; i++) {
    msg_queues[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}
```

### Alloc

```c
for (int i = 0; i < msgs_spray; i++) {
    msgsnd(msg_queues[i], &msgmsg_256, sizeof (msgmsg_256) - sizeof (long), 0);
}
```

> [!TIP]
> `idx` can be put at the start of `mtext` buffer so we can easily identify
> which `msg_msg` we're working with in gdb.

> [!NOTE]
> Size of `mtext` is `target_cache_size - 0x30`
> `size` parameter is `sizeof (msg_msg) - 8` for weird reasons

### Free

```c
msgrcv(msg_queues[idx], &msgmsg_256, sizeof (msgmsg_256) - sizeof (long),
       0x256, 0);
```

# Examples

## Arbitary read/write

```c
static struct msg_msg *alloc_msg(size_t len)
{
  struct msg_msg *msg;
  struct msg_msgseg **pseg;
  size_t alen;

  alen = min(len, DATALEN_MSG);
  msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT);
  if (msg == NULL)
	    return NULL;

  msg->next = NULL;
  msg->security = NULL;

  len -= alen;
  pseg = &msg->next;
  while (len > 0) {
    struct msg_msgseg *seg;

    cond_resched();

    alen = min(len, DATALEN_SEG);
    seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
    if (seg == NULL)
      goto out_err;
    *pseg = seg;
    seg->next = NULL;
    pseg = &seg->next;
    len -= alen;
  }

  return msg;

out_err:
  free_msg(msg);
	return NULL;
}
```

Note that `msg->next` is set to `NULL`, but later is referenced in `pseg`.
If during this period, we are able to use a race condition to overwrite
`msg->next`, then we can use it for arbitrary write.
