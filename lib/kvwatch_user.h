#ifndef KVWATCH_USER_H
#define KVWATCH_USER_H

#include <stddef.h>
#include "kvwatch_ioctl.h"

int kvw_open(int *fd, int nonblock);
void kvw_close(int *fd);

int kvw_subscribe(int fd, const char *key);
int kvw_unsubscribe(int fd, const char *key);

int kvw_set(int fd, const char *key, const void *val, kv_len_t len);
int kvw_set_string(int fd, const char *key, const char *val);

int kvw_get(int fd, const char *key, void *buf, kv_len_t buf_len, kv_len_t *out_len);
int kvw_get_string(int fd, const char *key, char *buf, size_t buflen);

int kvw_wait_event(int fd, char *keybuf, size_t keybuf_len, int timeout_ms);

int kvw_get_stats(int fd, struct kv_stats *st);
int kvw_set_max_events(int fd, kv_len_t maxev);

#endif
