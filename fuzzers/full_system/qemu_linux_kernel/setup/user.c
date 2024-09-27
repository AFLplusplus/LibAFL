#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
  const char *device = "/dev/harness";
  int         fd;

  // Open the device
  fd = open(device, O_RDWR);
  if (fd == -1) { return 1; }

  // Close the device
  if (close(fd) == -1) { return 1; }

  return 0;
}