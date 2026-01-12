#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/poll.h>

#include "kvwatch_kern.h"

#define DEVICE_NAME "kvwatch"

static int kv_open(struct inode *inode, struct file *filp)
{
    struct kv_subscriber *sub;

    sub = kzalloc(sizeof(*sub), GFP_KERNEL);
    if (!sub)
        return -ENOMEM;

    kv_subscriber_init(sub);
    filp->private_data = sub;

    return 0;
}

static int kv_release(struct inode *inode, struct file *filp)
{
    struct kv_subscriber *sub = filp->private_data;

    if (sub) {
        kv_subscriber_destroy(sub);
        kfree(sub);
        filp->private_data = NULL;
    }

    return 0;
}

static ssize_t kv_read(struct file *filp, char __user *buf,
                       size_t len, loff_t *ppos)
{
    struct kv_subscriber *sub = filp->private_data;
    struct kv_event *ev;
    char kbuf[KV_MAX_KEY_LEN];
    ssize_t ret;

    if (!sub)
        return -EINVAL;

    if (len < KV_MAX_KEY_LEN)
        return -EINVAL;

    if (!kv_events_pending(sub)) {
        if (filp->f_flags & O_NONBLOCK)
            return -EAGAIN;

        if (wait_event_interruptible(sub->wq, kv_events_pending(sub)))
            return -ERESTARTSYS;
    }

    ev = kv_event_dequeue(sub);
    if (!ev)
        return -EAGAIN;

    memcpy(kbuf, ev->key, KV_MAX_KEY_LEN);
    kfree(ev);

    if (copy_to_user(buf, kbuf, KV_MAX_KEY_LEN))
        return -EFAULT;

    ret = KV_MAX_KEY_LEN;
    return ret;
}

static __poll_t kv_poll(struct file *filp, poll_table *wait)
{
    struct kv_subscriber *sub = filp->private_data;
    __poll_t mask = 0;

    if (!sub)
        return EPOLLERR;

    poll_wait(filp, &sub->wq, wait);

    if (kv_events_pending(sub))
        mask |= EPOLLIN | EPOLLRDNORM;

    return mask;
}

static long kv_ioctl(struct file *filp,
                     unsigned int cmd, unsigned long arg)
{
    struct kv_subscriber *sub = filp->private_data;
    struct kv_pair pair;
    struct kv_key key;
    struct kv_stats stats;
    kv_len_t maxev;
    bool changed;
    int ret = 0;

    if (_IOC_TYPE(cmd) != KV_IOC_MAGIC)
        return -ENOTTY;

    switch (cmd) {
    case KV_IOC_SET:
        if (copy_from_user(&pair, (void __user *)arg, sizeof(pair)))
            return -EFAULT;

        pair.key[KV_MAX_KEY_LEN - 1] = '\0';

        ret = kv_store_set(&pair, &changed);
        if (ret)
            return ret;

        if (changed)
            kv_notify_key_changed(pair.key);

        return 0;

    case KV_IOC_GET:
        if (copy_from_user(&pair, (void __user *)arg, sizeof(pair)))
            return -EFAULT;

        pair.key[KV_MAX_KEY_LEN - 1] = '\0';

        ret = kv_store_get(&pair);
        if (ret)
            return ret;

        if (copy_to_user((void __user *)arg, &pair, sizeof(pair)))
            return -EFAULT;

        return 0;

    case KV_IOC_SUBSCRIBE:
        if (!sub)
            return -EINVAL;

        if (copy_from_user(&key, (void __user *)arg, sizeof(key)))
            return -EFAULT;

        key.name[KV_MAX_KEY_LEN - 1] = '\0';
        return kv_subscribe_key(sub, key.name);

    case KV_IOC_UNSUBSCRIBE:
        if (!sub)
            return -EINVAL;

        if (copy_from_user(&key, (void __user *)arg, sizeof(key)))
            return -EFAULT;

        key.name[KV_MAX_KEY_LEN - 1] = '\0';
        return kv_unsubscribe_key(sub, key.name);

    case KV_IOC_GET_STATS:
        if (!sub)
            return -EINVAL;

        kv_subscriber_get_stats(sub, &stats);

        if (copy_to_user((void __user *)arg, &stats, sizeof(stats)))
            return -EFAULT;

        return 0;

    case KV_IOC_SET_MAXEV:
        if (!sub)
            return -EINVAL;

        if (copy_from_user(&maxev, (void __user *)arg, sizeof(maxev)))
            return -EFAULT;

        kv_subscriber_set_max_events(sub, maxev);
        return 0;

    default:
        return -ENOTTY;
    }
}

static const struct file_operations kv_fops = {
    .owner          = THIS_MODULE,
    .open           = kv_open,
    .release        = kv_release,
    .read           = kv_read,
    .unlocked_ioctl = kv_ioctl,
    .poll           = kv_poll,
    .llseek         = noop_llseek,
};

static struct miscdevice kv_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &kv_fops,
    .mode  = 0666,
};

static int __init kv_init(void)
{
    int ret;

    ret = misc_register(&kv_miscdev);
    if (ret) {
        pr_err("kvwatch: misc_register failed: %d\n", ret);
        return ret;
    }

    pr_info("kvwatch: loaded, /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit kv_exit(void)
{
    misc_deregister(&kv_miscdev);
    kv_store_clear_all();
    pr_info("kvwatch: unloaded\n");
}

module_init(kv_init);
module_exit(kv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Varchenko Maxim");
MODULE_DESCRIPTION("Key-value store with per-key subscriptions and process notifications");
MODULE_VERSION("1.0");
