
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "template.h"

#define MAX_CORPUS_SIZE 10 * 1024 * 1024 //Max 10Mo

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int ret = template_run_some_data((char*)data, size);
  return ret;

}

static int filter(const struct dirent *name){return 1;}
static int test_one_corpus(char * corpus) {

  int ret;
  struct stat stat_;

  int fd = open(corpus, O_RDONLY);
  if (fd == -1) {
    printf("Error opening corpus\n");
    ret = -1;
    goto out;
  }
  
  stat(corpus, &stat_);

  int corpus_size = stat_.st_size;
  printf("Corpus: %s | Size : %d\n", corpus, corpus_size);

  if (corpus_size > MAX_CORPUS_SIZE) {
    printf("corpus size too big\n");
    ret = -1;
    goto out;
  }

  char * corpus_data = calloc(1, corpus_size);
  int bsize = read(fd, corpus_data, corpus_size);

  if (bsize != corpus_size) {
    printf("corpus size doesn't match readed size (%d != %d)!\n", bsize, corpus_size);
    ret = -1;
    goto out;
  }

  ret = LLVMFuzzerTestOneInput((const uint8_t*)corpus_data, (size_t)corpus_size);
  printf("ret=%d\n", ret);

  out:

    if (corpus_data) {
      free(corpus_data);
    }

    if (fd > 0) {
      close(fd);
    }
    return ret;

}

// simply RECOMPILE WITH -DTEST_CORPUS=1 OR -DTEST_ALL_CORPUS=1 to test corpus_evolution or crashes directory. 
#ifdef TEST_CORPUS
int main(int argc, char ** argv) {

  if (argc < 2) {
    printf("Usage : %s /path/to/corpus\n", argv[0]);
    return -1;
  } 
  
  char * corpus = argv[1];
  return test_one_corpus(corpus);
}
#endif

#ifdef TEST_ALL_CORPUS
int main(int argc, char ** argv) {

  int ret;
  struct dirent **namelist;
  char path_corpus[200] = {0};

  if (argc < 2) {
    printf("Usage : %s /path/to/corpusdir\n", argv[0]);
    return -1;
  } 
  
  int n = scandir(argv[1], &namelist, filter, alphasort);
  if (n == -1) {
    perror("scandir");
    exit(EXIT_FAILURE);
  }

  while (n--) {
    memset(path_corpus, 0, sizeof(path_corpus));

    if ((strcmp(namelist[n]->d_name, ".") == 0) || strcmp(namelist[n]->d_name, "..") ==0) {
      continue;
    }
    
    if ((strstr(namelist[n]->d_name, ".metadata")) || strstr(namelist[n]->d_name, ".lafl_lock")) {
      continue;
    }

    snprintf(path_corpus, sizeof(path_corpus), "%s/%s", argv[1], namelist[n]->d_name);
    ret = test_one_corpus(path_corpus);
  }

  free(namelist);
  return 0;


}
#endif