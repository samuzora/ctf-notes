// gcc -o demo -pthread demo.c
#include <sys/xattr.h>

// for syscalls
#include <unistd.h>
#include <sys/syscall.h>

// for userfaultfd
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>

// for threading and polling
#include <pthread.h>
#include <sys/mman.h>
#include <poll.h>

// for pprintf and other generic functions
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

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

int register_userfaultfd(void *addr, size_t len) {
  struct uffdio_register uffdio_register;
  struct uffdio_api uffdio_api;

  int uffd = syscall(0x143, 0); // or SYS_userfaultfd (must include <sys/syscall.h>)

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;

  assert(ioctl(uffd, UFFDIO_API, &uffdio_api) != -1);

  uffdio_register.range.start = (uint64_t)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;

  assert(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) != -1);

  pprintf("userfault registered on fd %d", uffd);

  return uffd;
}

int release_userfaultfd = 0;
void *handle_userfaultfd(void *args) {
  int uffd = *((int **)args)[0];
  void *userfault_region = *((void ***)args)[1];

  struct uffd_msg uffd_msg;
  struct pollfd pollfd;

  // there are 2 ways to eventually handle the pagefault:
  // 1. zero a region of the page
  struct uffdio_zeropage uffdio_zeropage;

  // or 2. copy the data out
  struct uffdio_copy uffdio_copy;

  // poll takes an array of fds to poll on, pass pollfd as an array with only 1 element
  while (poll(&pollfd, 1, -1) > 0) {
    assert(!(pollfd.revents & POLLERR || pollfd.revents & POLLHUP));

    assert(read(uffd, &uffd_msg, sizeof(uffd_msg)) > 0);

    // there are 5 possible event types
    // UFFD_EVENT_FORK, UFFD_EVENT_PAGEFAULT, UFFD_EVENT_MAP, UFFD_EVENT_REMOVE, UFFD_EVENT_UNMAP
    // we should only receive UFFD_EVENT_PAGEFAULT
    assert(uffd_msg.event == UFFD_EVENT_PAGEFAULT);

    pprintf("userfault triggered");

    // do somoething in main thread
    while (!release_userfaultfd) {}
    uffdio_zeropage.range.start = (size_t)userfault_region;
    uffdio_zeropage.range.len = 0x1000;
    uffdio_zeropage.mode = 0;

    pprintf("released %d", ioctl(uffd, UFFDIO_ZEROPAGE, &uffdio_zeropage));
  }

  return NULL;
}

void *trigger_release(void *) {
  for (int i = 1; i < 4; i++) {
    pprintf("waiting %d", i);
    sleep(1);
  }
  release_userfaultfd = 1;
  return NULL;
}

int main() {
  pthread_t thread;

  void *userfault_mem = (void *)0x1337000;
  // mmap will allocate a virtual page for us in the kernel, but this page isn't mapped to a physical page on memory
  // yet, for performance reasons
  assert(mmap(userfault_mem, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == userfault_mem);
  int uffd = register_userfaultfd(userfault_mem, 0x1000);

  void *args[2] = { (void *)&uffd, &userfault_mem };
  
  pthread_create(&thread, NULL, handle_userfaultfd, args);

  // after sleeping a while, update global variable to release thread
  pthread_create(&thread, NULL, trigger_release, NULL);

  // wait for userfault handler to be ready
  sleep(1);

  // do something to trigger access to mapped address
  // since this will be the first time we're accessing this page, it hasn't been mapped to physical memory, thus causing
  // a pagefault
  // but this may not always happen, because the kernel might somehow choose to pre-allocate the physical page before
  // even accessing it.
  // more info here https://stackoverflow.com/questions/65902372/does-loading-a-page-into-physical-memory-for-the-first-time-cause-a-major-page-f
  pprintf("%d", setxattr("./demo.c", "user.x", userfault_mem, 0x10, 0));
  pprintf("done read");

  release_userfaultfd = 0;

  // try a second time - this shouldn't cause a pagefault
  pprintf("%d", setxattr("./demo.c", "user.x", userfault_mem, 0x10, 0));
  pprintf("done read");

  return 0;
}
