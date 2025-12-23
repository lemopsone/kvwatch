#ifndef _KVWATCH_IOCTL_H
#define _KVWATCH_IOCTL_H

#include <linux/ioctl.h>

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u32 kv_len_t;
typedef __u64 kv_u64;
#else
#include <stdint.h>
typedef uint32_t kv_len_t;
typedef uint64_t kv_u64;
#endif

#define KV_IOC_MAGIC      'k'

#define KV_MAX_KEY_LEN    64
#define KV_MAX_VAL_LEN    256

struct kv_key {
    char name[KV_MAX_KEY_LEN];
};

struct kv_pair {
    char     key[KV_MAX_KEY_LEN];
    kv_len_t vlen;
    char     value[KV_MAX_VAL_LEN];
};

struct kv_stats {
    kv_len_t max_events;
    kv_len_t queue_len;
    kv_u64   dropped_events;
};

#define KV_IOC_SUBSCRIBE   _IOW(KV_IOC_MAGIC, 1, struct kv_key)
#define KV_IOC_UNSUBSCRIBE _IOW(KV_IOC_MAGIC, 2, struct kv_key)
#define KV_IOC_SET         _IOW(KV_IOC_MAGIC, 3, struct kv_pair)
#define KV_IOC_GET         _IOWR(KV_IOC_MAGIC, 4, struct kv_pair)
#define KV_IOC_GET_STATS   _IOR(KV_IOC_MAGIC, 5, struct kv_stats)
#define KV_IOC_SET_MAXEV   _IOW(KV_IOC_MAGIC, 6, kv_len_t)

#endif
