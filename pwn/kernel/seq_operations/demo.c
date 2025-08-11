#include <fcntl.h>
#include <assert.h>

#define seq_ops_spray 0x100
int seq_ops_fds[seq_ops_spray];
void alloc_seq_ops() {
  for (int i = 0; i < seq_ops_spray; i++) {
    seq_ops_fds[i] = open("/proc/self/stat", O_RDONLY);
    assert(seq_ops_fds[i] != -1);
  }
}

int main() {
  alloc_seq_ops();
}
