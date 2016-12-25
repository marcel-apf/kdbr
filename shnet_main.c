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


static int shnet_port_open(struct inode *inode, struct file *filp)
{
    struct shnet_port *port;

    port = container_of(inode->i_cdev, struct shnet_port, cdev);
    filp->private_data = port;

    if (!port) {
        pr_err("shnet: port open - no port data\n");
        return -1;
    }

    if (port->id <= 0) {
        pr_err("shnet: port open - bad port id %d\n", port->id);
        return -1;
    }

    pr_info("shnet: port opened with id %d\n", port->id);
    return 0;
}

static int shnet_port_release(struct inode *inode, struct file *filp)
{
    struct shnet_port *port;

    port = filp->private_data;
    if (!port) {
        pr_err("shnet: no port data\n");
        return 0;
    }

    pr_info("shnet port %d closed\n", port->id);
    return 0;
}

static const struct file_operations shnet_port_ops = {
    .owner          = THIS_MODULE,
    .open           = shnet_port_open,
    .release        = shnet_port_release,
};

static void shnet_delete_port(struct shnet_port *port)
{
    spin_lock_irq(&shnet_data.lock);

    list_del(&port->list);
    clear_bit(port->id, shnet_data.port_map);

    spin_unlock_irq(&shnet_data.lock);
}

static void shnet_destroy_device(struct shnet_port *port)
{
    device_destroy(shnet_data.class, port->cdev.dev);
    cdev_del(&port->cdev);
    kfree(port);
}

static int shnet_unregister_device(int id)
{
    struct shnet_port *port = NULL, *port2 = NULL;

    if (id <= 0 || id > SHNET_MAX_PORTS) {
        pr_err("shnet: unregister device - bad port id %d\n", port->id);
        return -EINVAL;
    }

    list_for_each_entry_safe(port, port2, &shnet_data.ports, list) {
        if (port->id == id) {
            pr_err("Unregistered the device on port %d\n", port->id);
            shnet_delete_port(port);
            shnet_destroy_device(port);
            return 0;
        }
    }

    return -ENODEV;
}

static int shnet_register_device(void)
{
    struct shnet_port *port;
    dev_t devt;
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
    devt = MKDEV(shnet_data.major, id);
    ret = cdev_add(&port->cdev, devt, 1);
    if (ret < 0) {
        pr_err("Error %d adding cdev for shnet port %d\n", ret, id);
        goto fail_cdev;
    }

    port->dev = device_create(shnet_data.class, NULL,
                              devt, port, "shnet%d", id);
    if (IS_ERR(port->dev)) {
        ret = PTR_ERR(port->dev);
        pr_err("Error %d creating device for shnet port %d\n", ret, id);
        goto fail_cdev;
    }

    pr_info("Registered a new device on port, %d major %d\n", port->id, shnet_data.major);
    return id;

fail_cdev:
    cdev_del(&port->cdev);
    shnet_delete_port(port);

fail_port:
    kfree(port);

fail:
    return ret;
}

static long shnet_ioctl(struct file *filp,
                        unsigned int cmd, unsigned long arg)
{
    int ret, port;

    pr_info("shnet driver ioctl called\n");

    if (_IOC_TYPE(cmd) != SHNET_IOC_MAGIC)
        return -ENOTTY;

    if (_IOC_NR(cmd) > SHNET_IOC_MAX)
        return -ENOTTY;

    switch (cmd) {
    case SHNET_REGISTER_DEVICE:
        ret = put_user(shnet_register_device(), (int __user *)arg);
        break;
    case SHNET_UNREGISTER_DEVICE:
        ret = get_user(port,  (int __user *)arg);
        if (!ret)
            ret = shnet_unregister_device(port);
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
    dev_t devt;
    int ret;

    ret = alloc_chrdev_region(&devt, 0, SHNET_MAX_PORTS, "shnet");
    if (ret < 0) {
        pr_err("Error %d allocating chrdev region for shnet\n", ret);
        return ret;
    }
    shnet_data.major = MAJOR(devt);

    cdev_init(&shnet_data.cdev, &shnet_ops);
    shnet_data.cdev.owner = THIS_MODULE;
    ret = cdev_add(&shnet_data.cdev, devt, 1);
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
                                   devt, NULL, "shnet");
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
    unregister_chrdev_region(devt, SHNET_MAX_PORTS);
    return ret;
} 
EXPORT_SYMBOL_GPL(shnet_init);

static void __exit shnet_exit(void)
{
    struct shnet_port *port = NULL, *port2 =NULL;

    list_for_each_entry_safe(port, port2, &shnet_data.ports, list) {
        shnet_delete_port(port);
        shnet_destroy_device(port);
    }

    device_destroy(shnet_data.class , MKDEV(shnet_data.major, 0));
    class_destroy(shnet_data.class);
    cdev_del(&shnet_data.cdev);
    unregister_chrdev_region(MKDEV(shnet_data.major, 0), SHNET_MAX_PORTS);

    pr_info("shnet driver unloaded\n"); 
} 
EXPORT_SYMBOL_GPL(shnet_exit);

module_init(shnet_init); 
module_exit(shnet_exit);
