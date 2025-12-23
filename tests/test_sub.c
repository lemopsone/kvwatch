#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kvwatch_user.h"

int main(int argc, char *argv[])
{
    const char *keyname = "my_key";
    struct kvw_client cli;
    char keybuf[KV_MAX_KEY_LEN];
    char valbuf[KV_MAX_VAL_LEN + 1];
    int event_idx = 0;

    if (argc > 1)
        keyname = argv[1];

    cli.fd = -1;
    if (kvw_open(&cli, 1) < 0) {
        perror("kvw_open");
        return 1;
    }

    if (kvw_subscribe(&cli, keyname) < 0) {
        perror("kvw_subscribe");
        kvw_close(&cli);
        return 1;
    }

    printf("Watching key '%s' for changes. Press Ctrl+C to stop.\n", keyname);

    for (;;) {
        int rc = kvw_wait_event(&cli, keybuf, sizeof(keybuf), -1);
        if (rc < 0) {
            perror("kvw_wait_event");
            break;
        }
        if (rc == 0)
            continue;

        if (kvw_get_string(&cli, keybuf, valbuf, sizeof(valbuf)) == 0) {
            event_idx++;
            printf("[event %d] key='%s' value='%s'\n",
                   event_idx, keybuf, valbuf);
        } else {
            event_idx++;
            printf("[event %d] key='%s' value not found\n",
                   event_idx, keybuf);
        }
    }

    kvw_close(&cli);
    return 0;
}
