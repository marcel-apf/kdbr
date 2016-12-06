/*
 * Kernel-based shared networking driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright 2016 Red Hat, Inc.
 * Copyright 2016 Oracle
 *
 * Authors:
 *   Marcel Apfelbaum <marcel@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marcel Apfelbaum");


#define SHNET_MAX_PORTS 255

#define SHNET_IOC_MAGIC 0xBA

#define SHNET_REGISTER_DEVICE       _IOR(SHNET_IOC_MAGIC, 0, int)
#define SHNET_UNREGISTER_DEVICE     _IOW(SHNET_IOC_MAGIC, 1, int)
#define SHNET_IOC_MAX               2

struct shnet_driver_data {
    struct class *class;
    struct device *dev;
    struct cdev cdev;
    int major;

    spinlock_t lock;

    DECLARE_BITMAP(port_map, SHNET_MAX_PORTS);
    struct list_head ports;
};
static struct shnet_driver_data shnet_data;

struct shnet_port {
    struct cdev cdev;
    struct device *dev;

    /* Next port in the list, head is in the shnet_data */
    struct list_head list;

    /* port id - device minor */
    int id;
};

static void shnet_unregister_device(struct shnet_port *port)
{
    spin_lock_irq(&shnet_data.lock);
    list_del(&port->list);
    clear_bit(port->id, shnet_data.port_map);
    spin_unlock_irq(&shnet_data.lock);

    pr_info("Unregistered the device on port %d\n", port->id);
}

static int shnet_port_open(struct inode *inode, struct file *filp)
{
    struct shnet_port *port;

    port = container_of(inode->i_cdev, struct shnet_port, cdev);
    filp->private_data = port;

    return 0;
}

static int shnet_port_release(struct inode *inode, struct file *filp)
{
    struct shnet_port *port;
    dev_t dev;

    port = filp->private_data;
    if (!port) {
        pr_err("shnet: no port data\n");
        return 0;
    }
    pr_info("Closing shnet port %d\n", port->id);
    dev = MKDEV(shnet_data.major, port->id);

    shnet_unregister_device(port);

    device_destroy(shnet_data.class , dev);
    cdev_del(&port->cdev);

    kfree(port);
    pr_info("shnet port %d closed\n", port->id);
    return 0;
}

static const struct file_operations shnet_port_ops = {
    .owner          = THIS_MODULE,
    .open           = shnet_port_open,
    .release        = shnet_port_release,
};

static int shnet_register_device(void)
{
    struct shnet_port *port;
    dev_t dev;
    int id;
    int ret;

    port = kmalloc(sizeof(*port), GFP_KERNEL);
    if (!port) {
        ret = -ENOMEM;
        goto fail;
    }

    spin_lock_irq(&shnet_data.lock);

    id = find_first_zero_bit(shnet_data.port_map, SHNET_MAX_PORTS);
    if (id == SHNET_MAX_PORTS) {
        spin_unlock_irq(&shnet_data.lock);
        ret = -ENOSPC;
        goto fail_port;
    }
    set_bit(id, shnet_data.port_map);
    port->id = id;
    list_add_tail(&port->list, &shnet_data.ports);

    spin_unlock_irq(&shnet_data.lock);

    cdev_init(&port->cdev, &shnet_port_ops);
    port->cdev.owner = THIS_MODULE;
    dev = MKDEV(shnet_data.major, id);
    ret = cdev_add(&port->cdev, dev, 1);
    if (ret < 0) {
        pr_err("Error %d adding cdev for shnet port %d\n", ret, id);
        goto fail_cdev;
    }

    port->dev = device_create(shnet_data.class, shnet_data.dev,
                              dev, port, "shnet%d", id);
    if (IS_ERR(port->dev)) {
        ret = PTR_ERR(port->dev);
        pr_err("Error %d creating device for shnet port %d\n", ret, id);
        goto fail_cdev;
    }

    pr_info("Registered a new device on port %d\n", port->id);
    return id;

fail_cdev:
    cdev_del(&port->cdev);
    shnet_unregister_device(port);

fail_port:
    kfree(port);

fail:
    return ret;
}

static long shnet_ioctl(struct file *filp,
                        unsigned int cmd, unsigned long arg)
{
    int ret;

    pr_info("shnet driver ioctl called\n");

    if (_IOC_TYPE(cmd) != SHNET_IOC_MAGIC)
        return -ENOTTY;

    if (_IOC_NR(cmd) > SHNET_IOC_MAX)
        return -ENOTTY;

    switch (cmd) {
    case SHNET_REGISTER_DEVICE:
        ret = put_user(shnet_register_device(), (int __user *)arg);
        break;
    default:
        return -ENOTTY;
    }

    return ret;
}

int shnet_release(struct inode *inode, struct file *filp)
{
        return 0;
}

static const struct file_operations shnet_ops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = shnet_ioctl,
    .open           = nonseekable_open,
    .release        = shnet_release,
};

static int __init shnet_init(void)
{
    dev_t dev;
    int ret;

    ret = alloc_chrdev_region(&dev, 0, SHNET_MAX_PORTS, "shnet");
    if (ret < 0) {
        pr_err("Error %d allocating chrdev region for shnet\n", ret);
        return ret;
    }
    shnet_data.major = MAJOR(dev);

    cdev_init(&shnet_data.cdev, &shnet_ops);
    shnet_data.cdev.owner = THIS_MODULE;
    ret = cdev_add(&shnet_data.cdev, dev, SHNET_MAX_PORTS);
    if (ret < 0) {
        pr_err("Error %d adding cdev for shnet\n", ret);
        goto fail_chrdev;
    }

    shnet_data.class = class_create(THIS_MODULE, "shnet");
    if (IS_ERR(shnet_data.class)) {
        ret = PTR_ERR(shnet_data.class);
        pr_err("Error %d creating shnet-class\n", ret);
        goto fail_cdev;
}

shnet_data.dev = device_create(shnet_data.class, NULL,
                               MKDEV(shnet_data.major, 0), NULL, "shnet");
    if (IS_ERR(shnet_data.dev)) {
        ret = PTR_ERR(shnet_data.dev);
        pr_err("Error %d creating shnet device\n", ret);
        goto fail_class;
    }

    spin_lock_init(&shnet_data.lock);
    INIT_LIST_HEAD(&shnet_data.ports);

    /* minor 0 is used by the shnet device */
    set_bit(0, shnet_data.port_map);

    pr_info("shnet driver loaded\n"); 
    return 0;


fail_class:
    class_destroy(shnet_data.class);

fail_cdev:
    cdev_del(&shnet_data.cdev);

fail_chrdev:
    unregister_chrdev_region(dev, SHNET_MAX_PORTS);
    return ret;
} 
EXPORT_SYMBOL_GPL(shnet_init);

static void __exit shnet_exit(void)
{
    struct shnet_port *port = NULL, *port2 =NULL;

    list_for_each_entry_safe(port, port2, &shnet_data.ports, list)
        shnet_unregister_device(port);

    device_destroy(shnet_data.class , MKDEV(shnet_data.major, 0));
    class_destroy(shnet_data.class);
    cdev_del(&shnet_data.cdev);
    unregister_chrdev_region(MKDEV(shnet_data.major, 0), SHNET_MAX_PORTS);

    pr_info("shnet driver unloaded\n"); 
} 
EXPORT_SYMBOL_GPL(shnet_exit);

module_init(shnet_init); 
module_exit(shnet_exit);
