#include <sys/xattr.h>
#include <unistd.h>
#include <string.h>

int main() {
  size_t payload[0x20];
  payload[0] = 0xdeadbeef;
  payload[1] = 0xcafebabe;

  setxattr("./demo.c", "user.x", payload, sizeof(payload), 0);
}
