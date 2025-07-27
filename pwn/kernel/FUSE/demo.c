#include <string.h>
#include <unistd.h>
#define _GNU_SOURCE
// for FUSE
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <pthread.h>

// other stuff
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

// gcc demo.c -o demo -static -pthread `pkg-config fuse3 --cflags --libs` -Os

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

static int do_getattr(const char *path, struct stat *st, struct fuse_file_info *info) {
	
	st->st_uid = getuid();
	st->st_gid = getgid(); 
	st->st_atime = time( NULL ); 
	st->st_mtime = time( NULL ); 
	
	if (strcmp(path, "/") == 0) {
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; 
	}
	else {
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {

	filler(buffer, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS); // Current Directory
	filler(buffer, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS); // Parent Directory
	
	if (strcmp(path, "/") == 0 ) {
		filler(buffer, "file1", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
		filler(buffer, "file2", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
	}
	return 0;
}

int unlock_fuse = 0;
static int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  pprintf("read %s, %d bytes, offset %d", path, size, offset);

  while (!unlock_fuse) {}
  return size;
}

// do_readdir and do_getattr are required to open the file
struct fuse_operations fuse_ops = {
  .read = do_read,
  .readdir = do_readdir,
  .getattr = do_getattr
};

void *fuse_setup(void *args) {
  struct fuse_args *fuse_args = (struct fuse_args *)args;
  struct fuse *fuse = fuse_new(fuse_args, &fuse_ops, sizeof(fuse_ops), NULL);
  assert(fuse != NULL);

  assert(mkdir("/tmp/fuse_dir", 0777) == 0);
  assert(fuse_mount(fuse, "/tmp/fuse_dir") == 0);

  struct fuse_session *fuse_session = fuse_get_session(fuse);
  assert(fuse_session != NULL);
  assert(fuse_set_signal_handlers(fuse_session) == 0);

  int fuse_fd = fuse_session_fd(fuse_session);

  pprintf("fusefs setup done, starting thread");

  fuse_loop_mt(fuse, fuse_fd);

  return NULL;

  // assert(mkdir("/tmp/fuse_dir", 0777) == 0);
  //
  // fuse_chan = fuse_mount("/tmp/fuse_dir", &fuse_args);
  // assert(fuse_chan > 0);
  //
  // fuse = fuse_new(fuse_chan, &fuse_args, &fuse_ops, sizeof(fuse_ops), NULL);
  // assert(fuse > 0);
  //
  // fuse_set_signal_handlers(fuse_get_session(fuse));
  // fuse_loop_mt(fuse);
}

int main(int argc, char **argv) {
  char *fuse_argv[0x10] = { argv[0] };
  struct fuse_args fuse_args = FUSE_ARGS_INIT(1, fuse_argv);

  pthread_t fuse_pthread;

  pthread_create(&fuse_pthread, NULL, fuse_setup, &fuse_args);

  sleep(5);

  // trigger the read operation
  char buf[0x10];
  int fd = open("/tmp/fuse_dir/file1", O_RDWR);
  read(fd, buf, 0x8);

  return 0;
}
