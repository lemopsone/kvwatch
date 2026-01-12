#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kvwatch_user.h"

int main(int argc, char *argv[])
{
    const char *key = "my_key";
    const char *val = "default";
    struct kvw_client cli;

    if (argc > 1)
        key = argv[1];
    if (argc > 2)
        val = argv[2];

    cli.fd = -1;
    if (kvw_open(&cli, 0) < 0) {
        perror("kvw_open");
        return 1;
    }

    if (kvw_set_string(&cli, key, val) < 0) {
        perror("kvw_set_string");
        kvw_close(&cli);
        return 1;
    }

    printf("[test_set] SET key='%s' value='%s'\n", key, val);

    kvw_close(&cli);
    return 0;
}
