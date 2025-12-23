#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kvwatch_user.h"

int main(int argc, char *argv[])
{
    const char *key = "stat_key";
    kv_len_t maxev = 4;
    struct kvw_client cli;
    struct kv_stats st;
    int i;

    if (argc > 1)
        key = argv[1];
    if (argc > 2) {
        unsigned long v = strtoul(argv[2], NULL, 10);
        if (v == 0)
            v = 1;
        if (v > 100000)
            v = 100000;
        maxev = (kv_len_t)v;
    }

    cli.fd = -1;
    if (kvw_open(&cli, 1) < 0) {
        perror("kvw_open");
        return 1;
    }

    if (kvw_set_max_events(&cli, maxev) < 0) {
        perror("kvw_set_max_events");
        kvw_close(&cli);
        return 1;
    }

    if (kvw_subscribe(&cli, key) < 0) {
        perror("kvw_subscribe");
        kvw_close(&cli);
        return 1;
    }

    for (i = 0; i < 10000; i++) {
        char vbuf[32];
        snprintf(vbuf, sizeof(vbuf), "val_%d", i);
        if (kvw_set_string(&cli, key, vbuf) < 0) {
            perror("kvw_set_string");
            break;
        }
    }

    if (kvw_get_stats(&cli, &st) < 0) {
        perror("kvw_get_stats");
        kvw_close(&cli);
        return 1;
    }

    printf("Stats for key='%s'\n", key);
    printf("  max_events     = %u\n", st.max_events);
    printf("  queue_len      = %u\n", st.queue_len);
    printf("  dropped_events = %llu\n",
           (unsigned long long)st.dropped_events);

    kvw_close(&cli);
    return 0;
}
