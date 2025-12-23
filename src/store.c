#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include "kvwatch_kern.h"

struct kv_item {
    struct hlist_node hnode;
    char     key[KV_MAX_KEY_LEN];
    kv_len_t vlen;
    char     value[KV_MAX_VAL_LEN];
};

static DEFINE_HASHTABLE(kv_items_ht, KV_ITEMS_HASH_BITS);
static DEFINE_SPINLOCK(kv_items_lock);

static u32 kv_hash_key(const char *key)
{
    u32 hash = 5381;
    int c;

    while ((c = (unsigned char)*key++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

static struct kv_item *kv_find_item_locked(const char *key, u32 hash)
{
    struct kv_item *it;

    hash_for_each_possible(kv_items_ht, it, hnode, hash) {
        if (strncmp(it->key, key, KV_MAX_KEY_LEN) == 0)
            return it;
    }

    return NULL;
}

int kv_store_set(const struct kv_pair *pair, bool *changed)
{
    struct kv_item *it;
    unsigned long flags;
    bool loc_changed = false;
    u32 hash;

    if (!pair || !changed)
        return -EINVAL;

    if (pair->vlen > KV_MAX_VAL_LEN)
        return -EINVAL;

    hash = kv_hash_key(pair->key);

    spin_lock_irqsave(&kv_items_lock, flags);

    it = kv_find_item_locked(pair->key, hash);
    if (!it) {
        it = kzalloc(sizeof(*it), GFP_ATOMIC);
        if (!it) {
            spin_unlock_irqrestore(&kv_items_lock, flags);
            return -ENOMEM;
        }
        strscpy(it->key, pair->key, sizeof(it->key));
        it->vlen = 0;
        memset(it->value, 0, sizeof(it->value));
        hash_add(kv_items_ht, &it->hnode, hash);
        loc_changed = true;
    }

    if (it->vlen != pair->vlen ||
        memcmp(it->value, pair->value, pair->vlen) != 0) {
        memcpy(it->value, pair->value, pair->vlen);
        it->vlen = pair->vlen;
        loc_changed = true;
    }

    spin_unlock_irqrestore(&kv_items_lock, flags);

    *changed = loc_changed;
    return 0;
}

int kv_store_get(struct kv_pair *pair)
{
    struct kv_item *it;
    unsigned long flags;
    int ret = -ENOENT;
    u32 hash;

    if (!pair)
        return -EINVAL;

    hash = kv_hash_key(pair->key);

    spin_lock_irqsave(&kv_items_lock, flags);
    it = kv_find_item_locked(pair->key, hash);
    if (it) {
        kv_len_t copy_len = it->vlen;

        if (copy_len > KV_MAX_VAL_LEN)
            copy_len = KV_MAX_VAL_LEN;

        memcpy(pair->value, it->value, copy_len);
        pair->vlen = copy_len;
        ret = 0;
    }
    spin_unlock_irqrestore(&kv_items_lock, flags);

    return ret;
}

void kv_store_clear_all(void)
{
    struct kv_item *it;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned int bkt;

    spin_lock_irqsave(&kv_items_lock, flags);
    hash_for_each_safe(kv_items_ht, bkt, tmp, it, hnode) {
        hash_del(&it->hnode);
        kfree(it);
    }
    spin_unlock_irqrestore(&kv_items_lock, flags);
}
