/* Intentionally insecure C — fixture for the c-cpp lane (cppcheck + flawfinder). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle(const char *user) {
    char buf[8];
    /* Buffer overflow: literal longer than the destination (cppcheck can prove). */
    strcpy(buf, "this string is way longer than eight bytes");

    char cmd[64];
    /* Command injection via unsanitized input passed to the shell. */
    sprintf(cmd, "ls %s", user);
    system(cmd);

    /* Unbounded read into a fixed stack buffer. */
    char line[16];
    gets(line);
    printf(buf);            /* format string: user-influenced buffer as format */
}

int main(int argc, char **argv) {
    if (argc > 1) handle(argv[1]);
    /* Memory leak: allocation never freed. */
    char *p = malloc(32);
    strcpy(p, "leak");
    return 0;
}
