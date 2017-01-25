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
 *   Yuval Shaia <yuval.shaia@oracle.com>
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
#include <linux/syscalls.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <asm/uaccess.h>
#include "shnet.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marcel Apfelbaum");

#define SHNET_MAX_PORTS 255

extern ssize_t process_vm_rw(pid_t pid,
                             const struct iovec __user *lvec,
                             unsigned long liovcnt,
                             const struct iovec __user *rvec,
                             unsigned long riovcnt,
                             unsigned long flags, int vm_write);


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

    /* connection ids map */
    struct idr conn_idr;
    struct mutex conn_mutex;

    /* port id - device minor */
    int id;
    pid_t pid;
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

static void shnet_print_iovec(const struct iovec *vec, int vlen)
{
    int i;

    for (i = 0; i < vlen; i++) {
        pr_info ("addr %p, len %ld", vec[i].iov_base, vec[i].iov_len);
    }
    pr_info("\n");
}

struct shnet_recv {
    struct shnet_req req;
    const struct iovec __user *vec;
    pid_t pid;
};

static struct shnet_req send_req;
static struct shnet_recv recv;

static int shnet_port_recv(struct shnet_port *port,
                           struct shnet_recv *recv,
                           const struct iovec __user *vec)
{
    pr_info("shnet_port_recv\n");

    if (!recv->req.vlen) {
        pr_err("Empty request!\n");
        return -EINVAL;
    }
    shnet_print_iovec(recv->req.vec, recv->req.vlen);

    recv->pid = current->pid;
    recv->vec = vec;
    return 0;
}

static int snhet_port_send(struct shnet_port *port,
                           struct shnet_req *req,
                           const struct iovec __user *vec)
{
    ssize_t ret;

    pr_info("shnet_port_send\n");
    shnet_print_iovec(req->vec, req->vlen);

    if (!req->vlen) {
        pr_err("Empty request!\n");
        return -EINVAL;
    }

    if (!recv.req.vlen) {
        pr_err("No recv req pending\n");
        return -EINVAL;
    }

    ret = process_vm_rw(recv.pid, vec, req->vlen,
                        recv.vec, recv.req.vlen, 0, 1);
    pr_info("shnet: sent %lu(%ld) bytes to pid %d, copied %u vecs into %u vecs\n",
            ret, (unsigned long)ret, recv.pid, req->vlen, recv.req.vlen);

    shnet_print_iovec(recv.req.vec, recv.req.vlen);

    return 0;
}

static int shnet_open_connection(struct shnet_port *port,
                                 struct shnet_connection *user_conn)
{
    int id, ret;
    struct shnet_connection *conn;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL)
        return -ENOMEM;
    memcpy(conn, user_conn, sizeof(*conn));

    idr_preload(GFP_KERNEL);
    mutex_lock(&port->conn_mutex);

    id = idr_alloc(&port->conn_idr, conn, 1, 0, GFP_KERNEL);

    mutex_unlock(&port->conn_mutex);
    idr_preload_end();
    if (id  <  0) {
        ret = id;
        goto err_conn;
    }

    pr_info("shnet open conn %d, r_id =%d, on port %d\n",
            id, conn->remote_id, port->id);

    return id;
err_conn:
    kfree(conn);

    return ret;
}

static int shnet_close_connection(struct shnet_port *port, int conn_id)
{
    struct shnet_connection *conn;
    int ret;

    mutex_lock(&port->conn_mutex);
    conn = idr_find(&port->conn_idr, conn_id);
    if (conn == NULL) {
        ret = -ENODEV;
        pr_err("shnet close connection, can't find id %d\n", conn_id);
        goto err;
    }

    idr_remove(&port->conn_idr, conn_id);
    kfree(conn);

    mutex_unlock(&port->conn_mutex);

    pr_info("shnet close  conn %d, r_id =%d, on port %d\n",
            conn_id, conn->remote_id, port->id);

    return 0;

err:
    mutex_unlock(&port->conn_mutex);
    return ret;
}

static long shnet_port_ioctl(struct file *filp,
                             unsigned int cmd, unsigned long arg)
{
    int ret, conn_id;
    struct shnet_connection conn;

    pr_info("shnet driver ioctl called\n");

    if (_IOC_TYPE(cmd) != SHNET_PORT_IOC_MAGIC)
        return -ENOTTY;

    if (_IOC_NR(cmd) > SHNET_PORT_IOC_MAX)
        return -ENOTTY;

    switch (cmd) {
    case SHNET_PORT_OPEN_CONN:
        ret = copy_from_user(&conn,
                             (struct shnet_connection __user *)arg,
                             sizeof(conn));
        if (!ret)
            ret = shnet_open_connection(filp->private_data, &conn);
        break;
    case SHNET_PORT_CLOSE_CONN:
        ret = get_user(conn_id,  (int __user *)arg);
        if (!ret)
            ret = shnet_close_connection(filp->private_data, conn_id);
        break;
    case SHNET_PORT_RECV:
        ret = copy_from_user(&recv.req,
                             (struct shnet_req __user *)arg,
                             sizeof(recv.req));
        if (!ret)
            ret = shnet_port_recv(filp->private_data, &recv,
                                  (const struct iovec __user *)arg);
        break;
    case SHNET_PORT_SEND:
        ret = copy_from_user(&send_req,
                             (struct shnet_req __user *)arg,
                             sizeof(send_req));
        if(!ret)
            ret = snhet_port_send(filp->private_data, &send_req,
                                  (const struct iovec __user *)arg);
        break;
    default:
        return -ENOTTY;
    }

    return ret;
}

static const struct file_operations shnet_port_ops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = shnet_port_ioctl,
    .open           = shnet_port_open,
    .release        = shnet_port_release,
};

static int shnet_conn_idr_cleanup(int id, void *p, void *data)
{
    struct shnet_connection *conn = p;

    kfree(conn);

    return 0;
}

static void shnet_delete_port(struct shnet_port *port)
{
    spin_lock_irq(&shnet_data.lock);

    list_del(&port->list);
    clear_bit(port->id, shnet_data.port_map);

    spin_unlock_irq(&shnet_data.lock);

    idr_for_each(&port->conn_idr, shnet_conn_idr_cleanup, NULL);
    idr_destroy(&port->conn_idr);
}

static void shnet_destroy_device(struct shnet_port *port)
{
    device_destroy(shnet_data.class, port->cdev.dev);
    cdev_del(&port->cdev);
    kfree(port);
}

static int shnet_unregister_port(int id)
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

static int shnet_register_port(void)
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
    port->pid = current->pid;
    list_add_tail(&port->list, &shnet_data.ports);

    spin_unlock_irq(&shnet_data.lock);

    mutex_init(&port->conn_mutex);
    idr_init(&port->conn_idr);

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
    case SHNET_REGISTER_PORT:
        ret = put_user(shnet_register_port(), (int __user *)arg);
        break;
    case SHNET_UNREGISTER_PORT:
        ret = get_user(port,  (int __user *)arg);
        if (!ret)
            ret = shnet_unregister_port(port);
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
