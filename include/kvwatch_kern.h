#ifndef _KVWATCH_KERN_H
#define _KVWATCH_KERN_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/spinlock.h>

#include "kvwatch_ioctl.h"

#define KV_ITEMS_HASH_BITS 6
#define KV_KEYS_HASH_BITS  6

struct kv_event {
    char key[KV_MAX_KEY_LEN];
    struct list_head list;
};

struct kv_subscriber {
    wait_queue_head_t wq;
    spinlock_t        events_lock;
    struct list_head  pending_events;
    struct list_head  subs;
    kv_len_t          max_events;
    kv_len_t          queue_len;
    kv_u64            dropped_events;
};

int  kv_store_set(const struct kv_pair *pair, bool *changed);
int  kv_store_get(struct kv_pair *pair);
void kv_store_clear_all(void);

void kv_subscriber_init(struct kv_subscriber *sub);
void kv_subscriber_destroy(struct kv_subscriber *sub);

int  kv_subscribe_key(struct kv_subscriber *sub, const char *key);
int  kv_unsubscribe_key(struct kv_subscriber *sub, const char *key);
void kv_unsubscribe_all(struct kv_subscriber *sub);

void kv_notify_key_changed(const char *key);

bool              kv_events_pending(struct kv_subscriber *sub);
struct kv_event * kv_event_dequeue(struct kv_subscriber *sub);
void              kv_events_flush(struct kv_subscriber *sub);

void kv_subscriber_get_stats(struct kv_subscriber *sub, struct kv_stats *out);
void kv_subscriber_set_max_events(struct kv_subscriber *sub, kv_len_t max_events);

#endif

#endif
