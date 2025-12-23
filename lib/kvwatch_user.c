#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>

#include "kvwatch_user.h"

int kvw_open(struct kvw_client *c, int nonblock)
{
    int flags = O_RDONLY;
    if (nonblock)
        flags |= O_NONBLOCK;

    c->fd = open("/dev/kvwatch", flags);
    if (c->fd < 0)
        return -1;

    return 0;
}

void kvw_close(struct kvw_client *c)
{
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
}

int kvw_subscribe(struct kvw_client *c, const char *key)
{
    struct kv_key k;

    if (!key)
        return -1;

    memset(&k, 0, sizeof(k));
    snprintf(k.name, KV_MAX_KEY_LEN, "%s", key);

    if (ioctl(c->fd, KV_IOC_SUBSCRIBE, &k) < 0)
        return -1;

    return 0;
}

int kvw_unsubscribe(struct kvw_client *c, const char *key)
{
    struct kv_key k;

    if (!key)
        return -1;

    memset(&k, 0, sizeof(k));
    snprintf(k.name, KV_MAX_KEY_LEN, "%s", key);

    if (ioctl(c->fd, KV_IOC_UNSUBSCRIBE, &k) < 0)
        return -1;

    return 0;
}

int kvw_set(struct kvw_client *c, const char *key, const void *val, kv_len_t len)
{
    struct kv_pair pair;

    if (!key || (!val && len > 0))
        return -1;

    memset(&pair, 0, sizeof(pair));
    snprintf(pair.key, KV_MAX_KEY_LEN, "%s", key);
    if (len > KV_MAX_VAL_LEN)
        len = KV_MAX_VAL_LEN;
    pair.vlen = len;
    if (len > 0 && val)
        memcpy(pair.value, val, len);

    if (ioctl(c->fd, KV_IOC_SET, &pair) < 0)
        return -1;

    return 0;
}

int kvw_set_string(struct kvw_client *c, const char *key, const char *val)
{
    kv_len_t len;

    if (!val)
        val = "";

    len = (kv_len_t)strlen(val);
    return kvw_set(c, key, val, len);
}

int kvw_get(struct kvw_client *c, const char *key, void *buf, kv_len_t buf_len, kv_len_t *out_len)
{
    struct kv_pair pair;

    if (!key || !buf)
        return -1;

    memset(&pair, 0, sizeof(pair));
    snprintf(pair.key, KV_MAX_KEY_LEN, "%s", key);

    if (ioctl(c->fd, KV_IOC_GET, &pair) < 0)
        return -1;

    if (pair.vlen > buf_len)
        pair.vlen = buf_len;

    if (pair.vlen > 0)
        memcpy(buf, pair.value, pair.vlen);

    if (out_len)
        *out_len = pair.vlen;

    return 0;
}

int kvw_get_string(struct kvw_client *c, const char *key, char *buf, size_t buflen)
{
    kv_len_t out_len;

    if (!buf || buflen == 0)
        return -1;

    if (kvw_get(c, key, buf, (kv_len_t)(buflen - 1), &out_len) < 0)
        return -1;

    buf[out_len] = '\0';
    return 0;
}

int kvw_wait_event(struct kvw_client *c, char *keybuf, size_t keybuf_len, int timeout_ms)
{
    struct pollfd pfd;
    ssize_t r;

    if (!keybuf || keybuf_len < KV_MAX_KEY_LEN)
        return -1;

    pfd.fd = c->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    for (;;) {
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0)
            return -1;
        if (pr == 0)
            return 0;
        if (pfd.revents & POLLIN)
            break;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            return -1;
    }

    memset(keybuf, 0, keybuf_len);
    r = read(c->fd, keybuf, KV_MAX_KEY_LEN);
    if (r <= 0)
        return -1;

    if ((size_t)r >= KV_MAX_KEY_LEN)
        keybuf[KV_MAX_KEY_LEN - 1] = '\0';
    else
        keybuf[r] = '\0';

    return 1;
}

int kvw_get_stats(struct kvw_client *c, struct kv_stats *st)
{
    if (!st)
        return -1;

    memset(st, 0, sizeof(*st));
    if (ioctl(c->fd, KV_IOC_GET_STATS, st) < 0)
        return -1;

    return 0;
}

int kvw_set_max_events(struct kvw_client *c, kv_len_t maxev)
{
    if (ioctl(c->fd, KV_IOC_SET_MAXEV, &maxev) < 0)
        return -1;

    return 0;
}
