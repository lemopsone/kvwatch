#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include "kvwatch_kern.h"

struct kv_key_entry {
    char key[KV_MAX_KEY_LEN];
    struct list_head subs;
    struct hlist_node hnode;
};

struct kv_subscription {
    struct kv_subscriber *sub;
    struct kv_key_entry  *key_entry;
    struct list_head      by_key;
    struct list_head      by_sub;
};

static DEFINE_HASHTABLE(kv_keys_ht, KV_KEYS_HASH_BITS);
static DEFINE_SPINLOCK(kv_keys_lock);

static u32 kv_hash_key(const char *key)
{
    u32 hash = 5381;
    int c;

    while ((c = (unsigned char)*key++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

static struct kv_key_entry *kv_find_key_entry_locked(const char *key, u32 hash)
{
    struct kv_key_entry *ke;

    hash_for_each_possible(kv_keys_ht, ke, hnode, hash) {
        if (strncmp(ke->key, key, KV_MAX_KEY_LEN) == 0)
            return ke;
    }

    return NULL;
}

bool kv_events_pending(struct kv_subscriber *sub)
{
    unsigned long flags;
    bool not_empty;

    spin_lock_irqsave(&sub->events_lock, flags);
    not_empty = !list_empty(&sub->pending_events);
    spin_unlock_irqrestore(&sub->events_lock, flags);

    return not_empty;
}

struct kv_event *kv_event_dequeue(struct kv_subscriber *sub)
{
    struct kv_event *ev = NULL;
    unsigned long flags;

    spin_lock_irqsave(&sub->events_lock, flags);
    if (!list_empty(&sub->pending_events)) {
        ev = list_first_entry(&sub->pending_events, struct kv_event, list);
        list_del(&ev->list);
        if (sub->queue_len > 0)
            sub->queue_len--;
    }
    spin_unlock_irqrestore(&sub->events_lock, flags);

    return ev;
}

void kv_events_flush(struct kv_subscriber *sub)
{
    struct kv_event *ev;
    struct kv_event *tmp;
    unsigned long flags;

    spin_lock_irqsave(&sub->events_lock, flags);
    list_for_each_entry_safe(ev, tmp, &sub->pending_events, list) {
        list_del(&ev->list);
        kfree(ev);
    }
    sub->queue_len = 0;
    spin_unlock_irqrestore(&sub->events_lock, flags);
}

static void kv_queue_event(struct kv_subscriber *sub, const char *key)
{
    struct kv_event *ev;
    unsigned long flags;

    spin_lock_irqsave(&sub->events_lock, flags);

    if (sub->queue_len >= sub->max_events) {
        sub->dropped_events++;
        spin_unlock_irqrestore(&sub->events_lock, flags);
        return;
    }

    ev = kzalloc(sizeof(*ev), GFP_ATOMIC);
    if (!ev) {
        sub->dropped_events++;
        spin_unlock_irqrestore(&sub->events_lock, flags);
        return;
    }

    strscpy(ev->key, key, sizeof(ev->key));
    list_add_tail(&ev->list, &sub->pending_events);
    sub->queue_len++;

    spin_unlock_irqrestore(&sub->events_lock, flags);

    wake_up_interruptible(&sub->wq);
}

void kv_subscriber_init(struct kv_subscriber *sub)
{
    init_waitqueue_head(&sub->wq);
    spin_lock_init(&sub->events_lock);
    INIT_LIST_HEAD(&sub->pending_events);
    INIT_LIST_HEAD(&sub->subs);
    sub->max_events = 1024;
    sub->queue_len = 0;
    sub->dropped_events = 0;
}

void kv_unsubscribe_all(struct kv_subscriber *sub)
{
    struct kv_subscription *s;
    struct kv_subscription *tmp;
    unsigned long flags;

    spin_lock_irqsave(&kv_keys_lock, flags);
    list_for_each_entry_safe(s, tmp, &sub->subs, by_sub) {
        struct kv_key_entry *ke = s->key_entry;

        list_del(&s->by_sub);
        list_del(&s->by_key);

        if (list_empty(&ke->subs)) {
            hash_del(&ke->hnode);
            kfree(ke);
        }

        kfree(s);
    }
    spin_unlock_irqrestore(&kv_keys_lock, flags);
}

void kv_subscriber_destroy(struct kv_subscriber *sub)
{
    kv_unsubscribe_all(sub);
    kv_events_flush(sub);
}

int kv_subscribe_key(struct kv_subscriber *sub, const char *key)
{
    struct kv_key_entry *ke;
    struct kv_subscription *s;
    unsigned long flags;
    size_t len;
    u32 hash;

    if (!sub || !key)
        return -EINVAL;

    len = strnlen(key, KV_MAX_KEY_LEN);
    if (len == 0)
        return -EINVAL;
    if (len >= KV_MAX_KEY_LEN)
        return -ENAMETOOLONG;

    s = kzalloc(sizeof(*s), GFP_KERNEL);
    if (!s)
        return -ENOMEM;

    hash = kv_hash_key(key);

    spin_lock_irqsave(&kv_keys_lock, flags);

    ke = kv_find_key_entry_locked(key, hash);
    if (!ke) {
        ke = kzalloc(sizeof(*ke), GFP_ATOMIC);
        if (!ke) {
            spin_unlock_irqrestore(&kv_keys_lock, flags);
            kfree(s);
            return -ENOMEM;
        }
        strscpy(ke->key, key, sizeof(ke->key));
        INIT_LIST_HEAD(&ke->subs);
        hash_add(kv_keys_ht, &ke->hnode, hash);
    }

    s->sub = sub;
    s->key_entry = ke;
    list_add(&s->by_key, &ke->subs);
    list_add(&s->by_sub, &sub->subs);

    spin_unlock_irqrestore(&kv_keys_lock, flags);

    return 0;
}

int kv_unsubscribe_key(struct kv_subscriber *sub, const char *key)
{
    struct kv_key_entry *ke;
    struct kv_subscription *s;
    struct kv_subscription *tmp;
    unsigned long flags;
    int ret = -ENOENT;
    u32 hash;

    if (!sub || !key)
        return -EINVAL;

    hash = kv_hash_key(key);

    spin_lock_irqsave(&kv_keys_lock, flags);

    ke = kv_find_key_entry_locked(key, hash);
    if (!ke) {
        spin_unlock_irqrestore(&kv_keys_lock, flags);
        return -ENOENT;
    }

    list_for_each_entry_safe(s, tmp, &ke->subs, by_key) {
        if (s->sub == sub) {
            list_del(&s->by_key);
            list_del(&s->by_sub);
            if (list_empty(&ke->subs)) {
                hash_del(&ke->hnode);
                kfree(ke);
            }
            kfree(s);
            ret = 0;
            break;
        }
    }

    spin_unlock_irqrestore(&kv_keys_lock, flags);
    return ret;
}

void kv_notify_key_changed(const char *key)
{
    struct kv_key_entry *ke;
    struct kv_subscription *s;
    unsigned long flags;
    u32 hash;

    if (!key)
        return;

    hash = kv_hash_key(key);

    spin_lock_irqsave(&kv_keys_lock, flags);
    ke = kv_find_key_entry_locked(key, hash);
    if (!ke) {
        spin_unlock_irqrestore(&kv_keys_lock, flags);
        return;
    }

    list_for_each_entry(s, &ke->subs, by_key) {
        struct kv_subscriber *sub = s->sub;
        kv_queue_event(sub, key);
    }

    spin_unlock_irqrestore(&kv_keys_lock, flags);
}

void kv_subscriber_get_stats(struct kv_subscriber *sub, struct kv_stats *out)
{
    unsigned long flags;

    if (!out)
        return;

    memset(out, 0, sizeof(*out));

    spin_lock_irqsave(&sub->events_lock, flags);
    out->max_events = sub->max_events;
    out->queue_len = sub->queue_len;
    out->dropped_events = sub->dropped_events;
    spin_unlock_irqrestore(&sub->events_lock, flags);
}

void kv_subscriber_set_max_events(struct kv_subscriber *sub, kv_len_t max_events)
{
    unsigned long flags;

    if (!max_events)
        max_events = 1;

    spin_lock_irqsave(&sub->events_lock, flags);
    sub->max_events = max_events;
    spin_unlock_irqrestore(&sub->events_lock, flags);
}
