#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

void *__libafl_raw_mmap(void *addr, size_t length, int prot, int flags, int fd,
                        off_t offset) {
  return (void *)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
}

int __libafl_raw_munmap(void *addr, size_t length) {
  return syscall(SYS_munmap, addr, length);
}

void *__libafl_raw_mremap(void *old_address, size_t old_size, size_t new_size,
                          int flags, void *new_address) {
  return (void *)syscall(SYS_mremap, old_address, old_size, new_size, flags,
                         new_address);
}

int __libafl_raw_mprotect(void *addr, size_t len, int prot) {
  return syscall(SYS_mprotect, addr, len, prot);
}

int __libafl_raw_madvise(void *addr, size_t length, int advice) {
  return syscall(SYS_madvise, addr, length, advice);
}

ssize_t __libafl_raw_write(int fd, const void *buf, size_t count) {
  return syscall(SYS_write, fd, buf, count);
}

ssize_t __libafl_raw_read(int fd, void *buf, size_t count) {
  return syscall(SYS_read, fd, buf, count);
}

void __libafl_raw_exit_group(int status) {
  syscall(SYS_exit_group, status);
}
