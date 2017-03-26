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
#include <linux/highmem.h>
#include <asm/uaccess.h>
#include "kdbr.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marcel Apfelbaum");

#define KDBR_MAX_PORTS 255

struct kdbr_driver_data {
	struct class *class;
	struct device *dev;
	struct cdev cdev;
	int major;

	spinlock_t lock;

	DECLARE_BITMAP(port_map, KDBR_MAX_PORTS);
	struct list_head ports;
};
static struct kdbr_driver_data kdbr_data;

struct kdbr_completion_elem {
	struct list_head list;
	struct kdbr_completion comp;
};

struct sg_vec {
	/* TODO: Replace with ring buffer */
	struct list_head list;
	int vlen; /* <= KDBR_MAX_IOVEC_LEN */
	struct page *userpage[KDBR_MAX_IOVEC_LEN];
	void *userptr[KDBR_MAX_IOVEC_LEN];
	int connection_id;
	unsigned long req_id;
};

struct comp_ring {
	/* List of 'completions' for this port */
	struct list_head list;
	struct mutex lock;
	wait_queue_head_t queue;
	char data_flag;
};

struct kdbr_port {
	struct cdev cdev;
	struct device *dev;

	/* Next port in the list, head is in the kdbr_data */
	struct list_head list;

	/* connection ids map */
	struct idr conn_idr;
	struct mutex conn_mutex;

	/*port's global id*/
	struct kdbr_gid gid;

	/* port id - device minor */
	int id;
	pid_t pid;

	struct comp_ring comps;
};

/* Global routing table */
struct peer_route {
	/* TODO: Replace with RB-tree */
	struct list_head list;
	struct peer_key {
		unsigned long net_id;
		unsigned long id;
		unsigned long queue;
	} peer_key;
	struct kdbr_port *port;
	struct kdbr_connection *conn;
};
struct list_head global_route;

static int add_global_route(unsigned long net_id, unsigned long id,
			    unsigned long queue, struct kdbr_port *port,
			    struct kdbr_connection *conn)
{
	/* TODO: No check is made to see if it is already there since we
	 * will change the implementation anyway */
	struct peer_route *peer_route = kmalloc(sizeof(*peer_route),
						GFP_KERNEL);
	if (!peer_route) {
		pr_info("Fail to alloc route\n");
		return -ENOMEM;
	}

	peer_route->peer_key.net_id = net_id;
	peer_route->peer_key.id = id;
	peer_route->peer_key.queue = queue;
	peer_route->port = port;
	peer_route->conn = conn;

	list_add(&peer_route->list, &global_route);

	return 0;
}

static void del_global_route(struct kdbr_port *port,
			     struct kdbr_connection *conn)
{
	struct peer_route *pos, *next;

	list_for_each_entry_safe(pos, next, &global_route, list) {
		if ((pos->port == port) && (pos->conn == conn)) {
			list_del(&pos->list);
			kfree(pos);
			return;
		}
	}
}

static int get_global_route(unsigned long net_id, unsigned long id,
			    unsigned long queue, struct kdbr_port **port,
			    struct kdbr_connection **conn)
{
	struct peer_route *pos, *next;

	list_for_each_entry_safe(pos, next, &global_route, list) {
		if ((pos->peer_key.net_id == net_id) && (pos->peer_key.id == id)
		    && (pos->peer_key.queue == queue)) {
			*port = pos->port;
			*conn = pos->conn;
			return 0;
		}
	}

	return -EINVAL;
}

static int kdbr_port_open(struct inode *inode, struct file *filp)
{
	struct kdbr_port *port;

	port = container_of(inode->i_cdev, struct kdbr_port, cdev);
	filp->private_data = port;

	if (!port) {
		pr_debug("kdbr: port open - no port data\n");
		return -1;
	}

	if (port->id <= 0) {
		pr_debug("kdbr: port open - bad port id %d\n", port->id);
		return -1;
	}

	pr_info("kdbr: port opened with id %d\n", port->id);
	return 0;
}

static int kdbr_port_release(struct inode *inode, struct file *filp)
{
	struct kdbr_port *port;

	port = filp->private_data;
	if (!port) {
		pr_debug("kdbr: no port data\n");
		return 0;
	}

	pr_info("kdbr port %d closed\n", port->id);
	return 0;
}

static void kdbr_print_iovec(const struct iovec *vec, int vlen)
{
	int i;

	for (i = 0; i < vlen; i++)
		pr_debug("addr %p, len %ld", vec[i].iov_base, vec[i].iov_len);

	pr_debug("\n");
}

int post_cqe(struct kdbr_port *port, int connection_id, unsigned long req_id,
	     int status)
{
	struct kdbr_completion_elem *comp_elem;

	pr_debug("post_cqe: port_id=%d, connection_id=%d, req_id=%ld, status=%d\n",
		 port->id, connection_id, req_id, status);

	comp_elem = kmalloc(sizeof(struct kdbr_completion_elem), GFP_KERNEL);
	if (!comp_elem) {
		pr_debug("Fail to allocate completion-event\n");
		return -EINVAL;
	}
	comp_elem->comp.req_id = req_id;
	comp_elem->comp.status = status;
	comp_elem->comp.connection_id = connection_id;
	mutex_lock(&port->comps.lock);
	list_add_tail(&comp_elem->list, &port->comps.list);
	mutex_unlock(&port->comps.lock);

	port->comps.data_flag = 1;

	wake_up_interruptible(&port->comps.queue);

	return 0;
}

static struct kdbr_connection *get_connection(struct kdbr_port *port,
					       int conn_id)
{
	struct kdbr_connection *conn;

	mutex_lock(&port->conn_mutex);
	conn = idr_find(&port->conn_idr, conn_id);
	mutex_unlock(&port->conn_mutex);
	if (!conn)
		pr_debug("Fail to find connection %d for port %d\n",
			 conn_id, port->id);

	return conn;
}

static void add_sg_vec(struct kdbr_connection *conn, struct sg_vec *sg_vec)
{
	mutex_lock(conn->sg_vecs_mutex);
	list_add(&sg_vec->list, conn->sg_vecs_list);
	mutex_unlock(conn->sg_vecs_mutex);
}

static struct sg_vec *get_sg_vec(struct kdbr_connection *conn, int vlen)
{
	struct sg_vec *sg_vec = NULL;

	mutex_lock(conn->sg_vecs_mutex);
	if (list_empty(conn->sg_vecs_list)) {
		pr_debug("conn %ld: No more buffers\n", conn->queue_id);
		goto out;
	}

	sg_vec = list_last_entry(conn->sg_vecs_list, struct sg_vec, list);
	if (!sg_vec) {
		pr_debug("conn %ld: No more buffers\n", conn->queue_id);
		goto out;
	}

	/* TODO: This limited implementation works only when top of the
	 * list sg_vec has at least requested buffers.
	 * In addition, no check is made with regards to buffers sizes */
	if (sg_vec->vlen < vlen) {
		pr_err("conn %ld: Top sg_vec is small (%d<%d)\n",
		       conn->queue_id, sg_vec->vlen, vlen);
		goto out;
	}

	list_del(&sg_vec->list);

out:
	mutex_unlock(conn->sg_vecs_mutex);
	return sg_vec;
}

static int kdbr_port_recv(struct kdbr_port *port, struct kdbr_req *req)
{
	int rc, i;
	int nr_pages;
	int pg_offs;
	struct kdbr_connection *conn;
	struct sg_vec *sg_vec;

	if (!req->vlen)
		return post_cqe(port, req->connection_id, req->req_id,
				KDBR_ERR_CODE_EMPTY_VEC);
	kdbr_print_iovec(req->vec, req->vlen);

	conn = get_connection(port, req->connection_id);
	if (!conn)
		return post_cqe(port, req->connection_id, req->req_id,
				KDBR_ERR_CODE_INV_CONN_ID);

	sg_vec = kmalloc(sizeof(*sg_vec), GFP_KERNEL);
	sg_vec->vlen = req->vlen;
	sg_vec->connection_id = req->connection_id;
	sg_vec->req_id = req->req_id;

	for (i = 0; i < sg_vec->vlen; i++) {
		nr_pages = (req->vec[i].iov_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		pg_offs = (unsigned long)req->vec[i].iov_base & (PAGE_SIZE - 1);

		/* TODO: Need optimization when several buffers share the
		 * same page */
		rc = get_user_pages_fast((unsigned long)req->vec[i].iov_base -
					 pg_offs, nr_pages, 1,
					 &sg_vec->userpage[i]);
		if (rc != nr_pages) {
			pr_debug("get_user_pages_fast, requested %d, got %d\n",
				 nr_pages, rc);
			return post_cqe(port, req->connection_id, req->req_id,
					KDBR_ERR_CODE_INV_ADDR);
		}

		sg_vec->userptr[i] = kmap(sg_vec->userpage[i]) + pg_offs;
		if (!sg_vec->userptr[i]) {
			pr_debug("kmap = NULL\n");
			return post_cqe(port, req->connection_id, req->req_id,
					KDBR_ERR_CODE_INV_ADDR);
		}
	}

	add_sg_vec(conn, sg_vec);

	return 0;
}

static int kdbr_port_send(struct kdbr_port *port, struct kdbr_req *req)
{
	int rc = 0, i;
	struct kdbr_peer *peer;
	struct kdbr_port *rport;
	struct kdbr_connection *conn, *rconn;
	struct sg_vec *sg_vec;

	pr_debug("kdbr_port_send, remote net id 0x%lx, remote id 0x%lx, remote queue %ld\n",
		 req->peer.rgid.net_id, req->peer.rgid.id, req->peer.rqueue);
	kdbr_print_iovec(req->vec, req->vlen);

	if (!req->vlen)
		return post_cqe(port, req->connection_id, req->req_id,
				KDBR_ERR_CODE_EMPTY_VEC);

	/* Get peer attributes */
	if (!req->peer.rqueue) {
		conn = get_connection(port, req->connection_id);
		if (!conn)
			return post_cqe(port, req->connection_id, req->req_id,
					KDBR_ERR_CODE_INV_CONN_ID);
		peer = &conn->peer;
	} else {
		peer = &req->peer;
	}
	rc = get_global_route(peer->rgid.net_id, peer->rgid.id, peer->rqueue,
			      &rport, &rconn);
	if (rc)
		return post_cqe(port, req->connection_id, req->req_id,
				KDBR_ERR_CODE_NO_PEER);

	/* Get next available buffers */
	sg_vec = get_sg_vec(rconn, req->vlen);
	if (!sg_vec)
		return post_cqe(port, req->connection_id, req->req_id,
				KDBR_ERR_CODE_NO_MORE_RECV_BUF);

	/* Copy to peer */
	for (i = 0; i < req->vlen; i++) {
		rc = copy_from_user(sg_vec->userptr[i], req->vec[i].iov_base,
				    req->vec[i].iov_len);
		if (rc) {
			post_cqe(rport, sg_vec->connection_id, sg_vec->req_id,
				 KDBR_ERR_CODE_RECV_BUF_PROT);
			kfree(sg_vec);
			return post_cqe(port, req->connection_id, req->req_id,
					KDBR_ERR_CODE_RECV_BUF_PROT);
		}

		SetPageDirty(sg_vec->userpage[i]);
		kunmap(sg_vec->userptr[i]);
		put_page(sg_vec->userpage[i]);
	}

	/* Post recv completion to peer */
	post_cqe(rport, sg_vec->connection_id, sg_vec->req_id, 0);

	kfree(sg_vec);

	/* Post send completion to requester */
	return post_cqe(port, req->connection_id, req->req_id, 0);
}

static int kdbr_open_connection(struct kdbr_port *port,
				struct kdbr_connection *user_conn)
{
	int id, ret;
	struct kdbr_connection *conn;

	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (conn == NULL) {
		pr_debug("Fail to alloc conn obj\n");
		return -ENOMEM;
	}

	memcpy(conn, user_conn, sizeof(*conn));
	conn->sg_vecs_list = kmalloc(sizeof(*conn->sg_vecs_list), GFP_KERNEL);
	INIT_LIST_HEAD(conn->sg_vecs_list);
	conn->sg_vecs_mutex = kmalloc(sizeof(*conn->sg_vecs_mutex), GFP_KERNEL);
	mutex_init(conn->sg_vecs_mutex);

	idr_preload(GFP_KERNEL);
	mutex_lock(&port->conn_mutex);

	id = idr_alloc(&port->conn_idr, conn, 1, 0, GFP_KERNEL);

	mutex_unlock(&port->conn_mutex);
	idr_preload_end();
	if (id  <  0) {
		ret = id;
		goto err_conn;
	}

	ret = add_global_route(port->gid.net_id, port->gid.id, conn->queue_id,
			       port, conn);
	if (ret) {
		/* TODO: Undo idr_alloc */
		ret = -ENOMEM;
		goto err_conn;
	}

	pr_info("kdbr open conn %d, r_net_id=0x%lx, r_id=0x%lx on port %d\n",
		id, conn->peer.rgid.net_id, conn->peer.rgid.id, port->id);

	return id;

err_conn:
	kfree(conn);

	return ret;
}

static int kdbr_close_connection(struct kdbr_port *port, int conn_id)
{
	struct kdbr_connection *conn;
	int ret;

	mutex_lock(&port->conn_mutex);
	conn = idr_find(&port->conn_idr, conn_id);
	if (conn == NULL) {
		ret = -ENODEV;
		pr_debug("kdbr close connection, can't find id %d\n", conn_id);
		goto err;
	}
	del_global_route(port, conn);
	kfree(conn->sg_vecs_list);
	kfree(conn->sg_vecs_mutex);

	idr_remove(&port->conn_idr, conn_id);
	kfree(conn);

	mutex_unlock(&port->conn_mutex);

	pr_info("kdbr close conn %d, r_net_id=0x%lx, r_id=0x%lx on port %d\n",
		conn_id, conn->peer.rgid.net_id, conn->peer.rgid.id, port->id);

	return 0;

err:
	mutex_unlock(&port->conn_mutex);

	return ret;
}

static long kdbr_port_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long arg)
{
	int ret, conn_id;
	struct kdbr_connection conn;

	pr_debug("kdbr driver ioctl called\n");

	if (_IOC_TYPE(cmd) != KDBR_PORT_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > KDBR_PORT_IOC_MAX)
		return -ENOTTY;

	switch (cmd) {
	case KDBR_PORT_OPEN_CONN:
		ret = copy_from_user(&conn,
				     (struct kdbr_connection __user *)arg,
				     sizeof(conn));
		if (!ret)
			ret = kdbr_open_connection(filp->private_data, &conn);
		break;
	case KDBR_PORT_CLOSE_CONN:
		ret = get_user(conn_id,  (int __user *)arg);
		if (!ret)
			ret = kdbr_close_connection(filp->private_data,
						    conn_id);
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}

ssize_t kdbr_port_read(struct file *file, char __user *buf, size_t size,
		       loff_t *ppos)
{
	struct kdbr_completion_elem *comp_elem, *next;
	int rc;
	size_t sz = 0;
	struct kdbr_port *port = file->private_data;

	wait_event_interruptible(port->comps.queue, port->comps.data_flag);

	mutex_lock(&port->comps.lock);
	list_for_each_entry_safe(comp_elem, next, &port->comps.list, list) {
		if (sz + sizeof(comp_elem->comp) > size)
			goto out;

		pr_debug("kdbr_port_read: req_id=%ld, status=%d\n",
			 comp_elem->comp.req_id, comp_elem->comp.status);
		rc = copy_to_user(buf + sz, &comp_elem->comp,
				  sizeof(comp_elem->comp));
		if (rc < 0) {
			pr_warn("Fail to copy to user buffer, rc=%d\n", rc);
			goto out;
		}

		sz += sizeof(comp_elem->comp);
		list_del(&comp_elem->list);
		kfree(comp_elem);
	}

out:
	if (list_empty(&port->comps.list))
		port->comps.data_flag = 0;
	mutex_unlock(&port->comps.lock);

	return sz;
}

ssize_t kdbr_port_write(struct file *file, const char __user *buf, size_t size,
		        loff_t *ppos)
{
	int rc, sz = 0;
	struct kdbr_req req;

	while (1) {
		if (sz + sizeof(req) > size)
			goto out;

		rc = copy_from_user(&req,
				    (struct kdbr_req __user *)(buf + sz),
				    sizeof(req));
		if (rc) {
			pr_debug("Fail to copy from user buf, pos=%d\n", sz);
			return sz;
		}

		if ((req.flags & KDBR_REQ_SIGNATURE) != KDBR_REQ_SIGNATURE) {
			pr_debug("Invalid message signature 0x%x\n",
				 req.flags & KDBR_REQ_SIGNATURE);
			return sz;
		}

		if ((req.flags & KDBR_REQ_POST_RECV) == KDBR_REQ_POST_RECV)
			rc = kdbr_port_recv(file->private_data, &req);

		if ((req.flags & KDBR_REQ_POST_SEND) == KDBR_REQ_POST_SEND)
			rc = kdbr_port_send(file->private_data, &req);

		sz += sizeof(req);
	}

out:
	return sz;
}

static const struct file_operations kdbr_port_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= kdbr_port_ioctl,
	.open		= kdbr_port_open,
	.release	= kdbr_port_release,
	.read		= kdbr_port_read,
	.write		= kdbr_port_write,
};

static int kdbr_conn_idr_cleanup(int id, void *p, void *data)
{
	kfree((struct kdbr_connection *)p);

	return 0;
}

static void kdbr_delete_port(struct kdbr_port *port)
{
	spin_lock_irq(&kdbr_data.lock);

	list_del(&port->list);
	clear_bit(port->id, kdbr_data.port_map);

	spin_unlock_irq(&kdbr_data.lock);

	idr_for_each(&port->conn_idr, kdbr_conn_idr_cleanup, NULL);
	idr_destroy(&port->conn_idr);
}

static void kdbr_destroy_device(struct kdbr_port *port)
{
	device_destroy(kdbr_data.class, port->cdev.dev);
	cdev_del(&port->cdev);
	kfree(port);
}

static int kdbr_unregister_port(int id)
{
	struct kdbr_port *port = NULL, *port2 = NULL;

	if (id <= 0 || id > KDBR_MAX_PORTS) {
		pr_debug("kdbr: unregister device, bad port id %d\n", port->id);
		return -EINVAL;
	}

	list_for_each_entry_safe(port, port2, &kdbr_data.ports, list) {
		if (port->id == id) {
			pr_info("Unregistered device on port %d\n", port->id);
			kdbr_delete_port(port);
			kdbr_destroy_device(port);
			return 0;
		}
	}

	return -ENODEV;
}

static int kdbr_register_port(struct kdbr_reg *reg)
{
	struct kdbr_port *port;
	dev_t devt;
	int id;
	int ret;

	port = kmalloc(sizeof(*port), GFP_KERNEL);
	if (!port) {
		ret = -ENOMEM;
		goto fail;
	}

	spin_lock_irq(&kdbr_data.lock);

	id = find_first_zero_bit(kdbr_data.port_map, KDBR_MAX_PORTS);
	if (id == KDBR_MAX_PORTS) {
		spin_unlock_irq(&kdbr_data.lock);
		ret = -ENOSPC;
		goto fail_port;
	}

	set_bit(id, kdbr_data.port_map);
	port->id = id;
	port->pid = current->pid;
	port->gid.net_id = reg->gid.net_id;
	port->gid.id = reg->gid.id;
	list_add_tail(&port->list, &kdbr_data.ports);

	reg->port = id;

	INIT_LIST_HEAD(&port->comps.list);
	mutex_init(&port->comps.lock);
	port->comps.data_flag = 0;
	init_waitqueue_head(&port->comps.queue);

	spin_unlock_irq(&kdbr_data.lock);

	mutex_init(&port->conn_mutex);
	idr_init(&port->conn_idr);

	cdev_init(&port->cdev, &kdbr_port_ops);
	port->cdev.owner = THIS_MODULE;
	devt = MKDEV(kdbr_data.major, id);
	ret = cdev_add(&port->cdev, devt, 1);
	if (ret < 0) {
		pr_debug("Error %d adding cdev for kdbr port %d\n", ret, id);
		goto fail_cdev;
	}

	port->dev = device_create(kdbr_data.class, NULL, devt, port, "kdbr%d",
				  id);
	if (IS_ERR(port->dev)) {
		ret = PTR_ERR(port->dev);
		pr_debug("Error %d creating device for kdbr port %d\n", ret,
			 id);
		goto fail_cdev;
	}

	pr_info("Registered device with gid [0x%lx,0x%lx] on port %d major %d\n",
		port->gid.net_id, port->gid.id, port->id,
		kdbr_data.major);

	return 0;

fail_cdev:
	cdev_del(&port->cdev);
	kdbr_delete_port(port);

fail_port:
	kfree(port);

fail:
	return ret;
}

static long kdbr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret, port;
	struct kdbr_reg reg;

	pr_debug("kdbr driver ioctl called\n");

	if (_IOC_TYPE(cmd) != KDBR_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > KDBR_IOC_MAX)
		return -ENOTTY;

	switch (cmd) {
	case KDBR_REGISTER_PORT:
		ret = copy_from_user(&reg, (struct kdbr_reg __user *)arg,
				     sizeof(reg));
		if (ret)
			return -EFAULT;

		ret = kdbr_register_port(&reg);
		if (!ret)
			ret = copy_to_user((struct kdbr_reg __user *)arg,
					   &reg, sizeof(reg));

		break;
	case KDBR_UNREGISTER_PORT:
		ret = get_user(port, (int __user *)arg);
		if (!ret)
			ret = kdbr_unregister_port(port);
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}

int kdbr_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations kdbr_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= kdbr_ioctl,
	.open		= nonseekable_open,
	.release	= kdbr_release,
};

static int __init kdbr_init(void)
{
	dev_t devt;
	int ret;

	ret = alloc_chrdev_region(&devt, 0, KDBR_MAX_PORTS, "kdbr");
	if (ret < 0) {
		pr_debug("Error %d allocating chrdev region for kdbr\n", ret);
		return ret;
	}
	kdbr_data.major = MAJOR(devt);

	cdev_init(&kdbr_data.cdev, &kdbr_ops);
	kdbr_data.cdev.owner = THIS_MODULE;
	ret = cdev_add(&kdbr_data.cdev, devt, 1);
	if (ret < 0) {
		pr_debug("Error %d adding cdev for kdbr\n", ret);
		goto fail_chrdev;
	}

	kdbr_data.class = class_create(THIS_MODULE, "kdbr");
	if (IS_ERR(kdbr_data.class)) {
		ret = PTR_ERR(kdbr_data.class);
		pr_debug("Error %d creating kdbr-class\n", ret);
		goto fail_cdev;
	}

	kdbr_data.dev = device_create(kdbr_data.class, NULL, devt, NULL,
				      "kdbr");
	if (IS_ERR(kdbr_data.dev)) {
		ret = PTR_ERR(kdbr_data.dev);
		pr_debug("Error %d creating kdbr device\n", ret);
		goto fail_class;
	}

	spin_lock_init(&kdbr_data.lock);
	INIT_LIST_HEAD(&kdbr_data.ports);

	INIT_LIST_HEAD(&global_route);

	/* minor 0 is used by the kdbr device */
	set_bit(0, kdbr_data.port_map);

	pr_info("kdbr driver loaded\n");
	return 0;


fail_class:
	class_destroy(kdbr_data.class);

fail_cdev:
	cdev_del(&kdbr_data.cdev);

fail_chrdev:
	unregister_chrdev_region(devt, KDBR_MAX_PORTS);

	return ret;
}
EXPORT_SYMBOL_GPL(kdbr_init);

static void __exit kdbr_exit(void)
{
	struct kdbr_port *port = NULL, *port2 = NULL;

	list_for_each_entry_safe(port, port2, &kdbr_data.ports, list) {
		kdbr_delete_port(port);
		kdbr_destroy_device(port);
	}

	device_destroy(kdbr_data.class, MKDEV(kdbr_data.major, 0));
	class_destroy(kdbr_data.class);
	cdev_del(&kdbr_data.cdev);
	unregister_chrdev_region(MKDEV(kdbr_data.major, 0), KDBR_MAX_PORTS);

	pr_info("kdbr driver unloaded\n");
}
EXPORT_SYMBOL_GPL(kdbr_exit);

module_init(kdbr_init);
module_exit(kdbr_exit);
