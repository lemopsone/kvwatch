#ifndef KVWATCH_USER_H
#define KVWATCH_USER_H

#include <stddef.h>
#include "kvwatch_ioctl.h"

struct kvw_client {
    int fd;
};

int kvw_open(struct kvw_client *c, int nonblock);
void kvw_close(struct kvw_client *c);

int kvw_subscribe(struct kvw_client *c, const char *key);
int kvw_unsubscribe(struct kvw_client *c, const char *key);

int kvw_set(struct kvw_client *c, const char *key, const void *val, kv_len_t len);
int kvw_set_string(struct kvw_client *c, const char *key, const char *val);

int kvw_get(struct kvw_client *c, const char *key, void *buf, kv_len_t buf_len, kv_len_t *out_len);
int kvw_get_string(struct kvw_client *c, const char *key, char *buf, size_t buflen);

int kvw_wait_event(struct kvw_client *c, char *keybuf, size_t keybuf_len, int timeout_ms);

int kvw_get_stats(struct kvw_client *c, struct kv_stats *st);
int kvw_set_max_events(struct kvw_client *c, kv_len_t maxev);

#endif
