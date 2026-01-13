#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kvwatch_user.h"

int main(int argc, char *argv[])
{
    const char *key = "my_key";
    const char *val = "default";
    int fd = -1;

    if (argc > 1)
        key = argv[1];
    if (argc > 2)
        val = argv[2];

    if (kvw_open(&fd, 0) < 0) {
        perror("kvw_open");
        return 1;
    }

    if (kvw_set_string(fd, key, val) < 0) {
        perror("kvw_set_string");
        kvw_close(&fd);
        return 1;
    }

    printf("[test_set] SET key='%s' value='%s'\n", key, val);

    kvw_close(&fd);
    return 0;
}
