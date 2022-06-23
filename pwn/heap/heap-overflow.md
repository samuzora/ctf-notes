# Heap Overflow

## What 

The heap grows upwards (to higher mem addresses), as opposed to stack which grows downwards (to lower mem addresses).

It's used when a program requests additional memory from the OS. 

This is usually done via `malloc()` or `dlmalloc()`. `malloc()` takes an integer specifying the size of the chunk allocated.

### Chunk

A chunk is a segment of data in the heap. The chunk looks like this:

```

|                           |
+---------------------------+ -
| Chunk size = 0x40 | Flags | |
+---------------------------+ |
|           DATA            | | 
|           DATA            | | -> 1 chunk
|           DATA            | |
|           DATA            | |
+---------------------------+ -
| Chunk size        | Flags |
+---------------------------+
|            ...            |

(each row is 8 bytes)

```

When a chunk is allocated, the chunk's size is first declared in the first 5 bytes of the header (last 3 bytes are used for AMP flags).

The actual data is after the header. The number of bytes allocated here depends on the size declared in header.

## Overflow

```
gef➤  x/20wx 0x804b1b0
0x804b1b0:      0x00000061      0x00000000      0x00000000      0x00000011
0x804b1c0:      0x00000002      0x0804b1d0      0x00000000      0x00000011
0x804b1d0:      0x00000062      0x00000000      0x00000000      0x00021e29
0x804b1e0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b1f0:      0x00000000      0x00000000      0x00000000      0x00000000
```

Overflow can occur if the size declared is not the actual size of the data. This can lead to arbitrary writes on the heap. 

As can be seen from the diagram, there is a 8-byte gap between each chunk, so we need to overflow `size+0x8` to the next chunk.

When overflow occurs, several things can occur.

1. Overwriting of other chunks
	* This can result in certain check bypasses and possibly get us the flag
	* eg. a can overflow into 0x804b1d0, overwriting chunk b's value


2. Overwriting of next free chunk address
	* We can use this to get a Write-What-Where primitive, allowing us to overwrite GOT etc.
	* eg. a can overflow into 0x804b1c0, overwriting where chunk b is written
