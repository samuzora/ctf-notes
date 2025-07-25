# `seq_operations` struct

> page: `kmalloc-cg-32`
> ROP: 

## Interacting with `seq_operations`

```c
struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
```

### Alloc

```c
int fd = open("/proc/self/stat", O_RDONLY);
```

### Trigger `seq_operations->start`

```c
read(fd, buf, size);
```
