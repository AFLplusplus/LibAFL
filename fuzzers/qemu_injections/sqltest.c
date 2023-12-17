#include <sqlite3.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
  int i;
  for (i = 0; i < argc; i++) {
    printf("%s=%s ", azColName[i], argv[i] ? argv[i] : "NULL");
  }
  printf("\n");
  return 0;
}

int LLVMFuzzerTestOneInput(char *data, size_t len) {
  sqlite3 *db;
  char    *err_msg = 0, query[1024];
  int      rc = sqlite3_open_v2("example.db", &db, SQLITE_OPEN_READONLY, 0);

  unsigned char x = data[0];
  ++data;
  --len;
  if (data[len - 1] != 0) data[len - 1] = 0;
  printf("x:%u data:%s\n", x, data);

  if (x < 128) {
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return 1;
    }

    snprintf(
        query, sizeof(query),
        "SELECT * FROM MyTable where user = \"user1\" and password = \"%s\"",
        data);

    fprintf(stderr, "query: %s\n", query);
    rc = sqlite3_exec(db, query, callback, 0, &err_msg);
    fprintf(stderr, "done.\n");

    if (rc == SQLITE_OK) {
      fprintf(stderr, "Success!\n");
    } else {
      fprintf(stderr, "Failed to execute query: %s\n", err_msg);
      sqlite3_free(err_msg);
    }

    sqlite3_close(db);

  } else {
    snprintf(query, sizeof(query), "/usr/bin/id \"%s\"", data);
    fprintf(stderr, "CMD=%s %p\n", query, query);
    system(query);
    fprintf(stderr, "done.\n");
  }

  return 0;
}

int main(int argc, char **argv) {
  char    pw[16];
  ssize_t len = 1;

  memset(pw, 0, sizeof(pw));
  if (argc > 1) {
    if ((len = read(0, pw, sizeof(pw) - 1)) < 4) {
      fprintf(stderr, "Error: short read from stdin\n");
      return -1;
    }
  }

  return LLVMFuzzerTestOneInput(pw, (size_t)len + 1);
}
