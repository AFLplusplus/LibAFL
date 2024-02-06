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

  if (data[0] % 2) {
    int rc = sqlite3_open_v2("example.db", &db, SQLITE_OPEN_READONLY, 0);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return 1;
    }

    snprintf(
        query, sizeof(query),
        "SELECT * FROM MyTable where user = \"user1\" and password = \"%s\"",
        data);

    rc = sqlite3_exec(db, query, callback, 0, &err_msg);

    if (rc != SQLITE_OK) { sqlite3_free(err_msg); }

    sqlite3_close(db);

  } else {
    snprintf(query, sizeof(query), "/usr/bin/id \"%s\"", data);
    system(query);
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
