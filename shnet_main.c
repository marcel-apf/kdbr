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
#include "shnet.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marcel Apfelbaum");

#define SHNET_MAX_PORTS 255

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

struct shnet_completion_elem {
	struct list_head list;
	struct shnet_completion comp;
};

struct sg_vec {
	/* TODO: Replace with ring buffer */
	struct list_head list;
	int vlen; /* <= SHNET_MAX_IOVEC_LEN */
	struct page *userpage[SHNET_MAX_IOVEC_LEN];
	void *userptr[SHNET_MAX_IOVEC_LEN];
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

struct shnet_port {
	struct cdev cdev;
	struct device *dev;

	/* Next port in the list, head is in the shnet_data */
	struct list_head list;

	/* connection ids map */
	struct idr conn_idr;
	struct mutex conn_mutex;

	/*port's global id*/
	struct shnet_gid gid;

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
	struct shnet_port *port;
	struct shnet_connection *conn;
};
struct list_head global_route;

static int add_global_route(unsigned long net_id, unsigned long id,
			    unsigned long queue, struct shnet_port *port,
			    struct shnet_connection *conn)
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

static void del_global_route(struct shnet_port *port,
			     struct shnet_connection *conn)
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
			    unsigned long queue, struct shnet_port **port,
			    struct shnet_connection **conn)
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

static int shnet_port_open(struct inode *inode, struct file *filp)
{
	struct shnet_port *port;

	port = container_of(inode->i_cdev, struct shnet_port, cdev);
	filp->private_data = port;

	if (!port) {
		pr_debug("shnet: port open - no port data\n");
		return -1;
	}

	if (port->id <= 0) {
		pr_debug("shnet: port open - bad port id %d\n", port->id);
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
		pr_debug("shnet: no port data\n");
		return 0;
	}

	pr_info("shnet port %d closed\n", port->id);
	return 0;
}

static void shnet_print_iovec(const struct iovec *vec, int vlen)
{
	int i;

	for (i = 0; i < vlen; i++)
		pr_debug("addr %p, len %ld", vec[i].iov_base, vec[i].iov_len);

	pr_debug("\n");
}

int post_cqe(struct shnet_port *port, int connection_id, unsigned long req_id,
	     int status)
{
	struct shnet_completion_elem *comp_elem;

	pr_debug("post_cqe: port_id=%d, connection_id=%d, req_id=%ld, status=%d\n",
		 port->id, connection_id, req_id, status);

	comp_elem = kmalloc(sizeof(struct shnet_completion_elem), GFP_KERNEL);
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

static struct shnet_connection *get_connection(struct shnet_port *port,
					       int conn_id)
{
	struct shnet_connection *conn;

	mutex_lock(&port->conn_mutex);
	conn = idr_find(&port->conn_idr, conn_id);
	mutex_unlock(&port->conn_mutex);
	if (!conn)
		pr_debug("Fail to find connection %d for port %d\n",
			 conn_id, port->id);

	return conn;
}

static void add_sg_vec(struct shnet_connection *conn, struct sg_vec *sg_vec)
{
	list_add(&sg_vec->list, conn->sg_vecs_list);
}

static struct sg_vec *get_sg_vec(struct shnet_connection *conn, int vlen)
{
	struct sg_vec *sg_vec;

	if (list_empty(conn->sg_vecs_list)) {
		pr_debug("conn %ld: No more buffers\n", conn->queue_id);
		return NULL;
	}

	sg_vec = list_first_entry(conn->sg_vecs_list, struct sg_vec, list);

	/* TODO: This limited implementation works only when top of the
	 * list sg_vec has at least requested buffers.
	 * In addition, no check is made with regards to buffers sizes */
	if (sg_vec->vlen < vlen) {
		pr_debug("conn %ld: Top sg_vec is small\n", conn->queue_id);
		return NULL;
	}

	list_del(&sg_vec->list);

	return sg_vec;
}

static int shnet_port_recv(struct shnet_port *port, struct shnet_req *req)
{
	int rc, i;
	int nr_pages;
	int pg_offs;
	struct shnet_connection *conn;
	struct sg_vec *sg_vec;

	if (!req->vlen)
		return post_cqe(port, req->connection_id, req->req_id,
				SHNET_ERR_CODE_EMPTY_VEC);
	shnet_print_iovec(req->vec, req->vlen);

	conn = get_connection(port, req->connection_id);
	if (!conn)
		return post_cqe(port, req->connection_id, req->req_id,
				SHNET_ERR_CODE_INV_CONN_ID);

	sg_vec = kmalloc(sizeof(*sg_vec), GFP_KERNEL);
	sg_vec->vlen = req->vlen;
	sg_vec->connection_id = req->connection_id;
	sg_vec->req_id = req->req_id;

	for (i = 0; i < sg_vec->vlen; i++) {
		nr_pages = (req->vec[i].iov_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		pg_offs = (unsigned long)req->vec[i].iov_base & (PAGE_SIZE - 1);

		/* TODO: Need optimisation when several buffers share the
		 * same page */
		rc = get_user_pages_fast((unsigned long)req->vec[i].iov_base -
					 pg_offs, nr_pages, 1,
					 &sg_vec->userpage[i]);
		if (rc != nr_pages) {
			pr_debug("get_user_pages_fast, requested %d, got %d\n",
				 nr_pages, rc);
			return post_cqe(port, req->connection_id, req->req_id,
					SHNET_ERR_CODE_INV_ADDR);
		}

		sg_vec->userptr[i] = kmap(sg_vec->userpage[i]) + pg_offs;
		if (!sg_vec->userptr[i]) {
			pr_debug("kmap = NULL\n");
			return post_cqe(port, req->connection_id, req->req_id,
					SHNET_ERR_CODE_INV_ADDR);
		}
	}

	add_sg_vec(conn, sg_vec);

	return 0;
}

static int snhet_port_send(struct shnet_port *port, struct shnet_req *req)
{
	int rc = 0, i;
	struct shnet_peer *peer;
	struct shnet_port *rport;
	struct shnet_connection *conn, *rconn;
	struct sg_vec *sg_vec;

	pr_debug("shnet_port_send, remote net id 0x%lx, remote id 0x%lx, remote queue %ld\n",
		req->peer.rgid.net_id, req->peer.rgid.id, req->peer.rqueue);
	shnet_print_iovec(req->vec, req->vlen);

	if (!req->vlen)
		return post_cqe(port, req->connection_id, req->req_id,
				SHNET_ERR_CODE_EMPTY_VEC);

	/* Get peer attributes */
	if (!req->peer.rqueue) {
		conn = get_connection(port, req->connection_id);
		if (!conn)
			return post_cqe(port, req->connection_id, req->req_id,
					SHNET_ERR_CODE_INV_CONN_ID);
		peer = &conn->peer;
	} else {
		peer = &req->peer;
	}
	rc = get_global_route(peer->rgid.net_id, peer->rgid.id, peer->rqueue,
			      &rport, &rconn);
	if (rc)
		return post_cqe(port, req->connection_id, req->req_id,
				SHNET_ERR_CODE_NO_PEER);

	/* Get next available buffers */
	sg_vec = get_sg_vec(rconn, req->vlen);
	if (!sg_vec)
		return post_cqe(port, req->connection_id, req->req_id,
				SHNET_ERR_CODE_NO_MORE_RECV_BUF);

	/* Copy to peer */
	for (i = 0; i < req->vlen; i++) {
		rc = copy_from_user(sg_vec->userptr[i], req->vec[i].iov_base,
				    req->vec[i].iov_len);
		if (rc) {
			post_cqe(rport, sg_vec->connection_id, sg_vec->req_id,
				 SHNET_ERR_CODE_RECV_BUF_PROT);
			kfree(sg_vec);
			return post_cqe(port, req->connection_id, req->req_id,
					SHNET_ERR_CODE_RECV_BUF_PROT);
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

static int shnet_open_connection(struct shnet_port *port,
				 struct shnet_connection *user_conn)
{
	int id, ret;
	struct shnet_connection *conn;

	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (conn == NULL) {
		pr_debug("Fail to alloc conn obj\n");
		return -ENOMEM;
	}

	memcpy(conn, user_conn, sizeof(*conn));
	conn->sg_vecs_list = kmalloc(sizeof(*conn->sg_vecs_list), GFP_KERNEL);
	INIT_LIST_HEAD(conn->sg_vecs_list);

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

	pr_info("shnet open conn %d, r_net_id=0x%lx, r_id=0x%lx on port %d\n",
		id, conn->peer.rgid.net_id, conn->peer.rgid.id, port->id);

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
		pr_debug("shnet close connection, can't find id %d\n", conn_id);
		goto err;
	}
	del_global_route(port, conn);
	kfree(conn->sg_vecs_list);

	idr_remove(&port->conn_idr, conn_id);
	kfree(conn);

	mutex_unlock(&port->conn_mutex);

	pr_info("shnet close conn %d, r_net_id=0x%lx, r_id=0x%lx on port %d\n",
		conn_id, conn->peer.rgid.net_id, conn->peer.rgid.id, port->id);

	return 0;

err:
	mutex_unlock(&port->conn_mutex);

	return ret;
}

static long shnet_port_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long arg)
{
	int ret, conn_id;
	struct shnet_connection conn;

	pr_debug("shnet driver ioctl called\n");

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
			ret = shnet_close_connection(filp->private_data,
						     conn_id);
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}

ssize_t shnet_port_read(struct file *file, char __user *buf, size_t size,
			loff_t *ppos)
{
	struct shnet_completion_elem *comp_elem, *next;
	int rc;
	size_t sz = 0;
	struct shnet_port *port = file->private_data;

	wait_event_interruptible(port->comps.queue, port->comps.data_flag);

	mutex_lock(&port->comps.lock);
	list_for_each_entry_safe(comp_elem, next, &port->comps.list, list) {
		if (sz + sizeof(comp_elem->comp) > size)
			goto out;

		pr_debug("shnet_port_read: req_id=%ld, status=%d\n",
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

ssize_t shnet_port_write(struct file *file, const char __user *buf, size_t size,
			 loff_t *ppos)
{
	int rc, sz = 0;
	struct shnet_req req;

	while (1) {
		if (sz + sizeof(req) > size)
			goto out;

		rc = copy_from_user(&req,
				    (struct shnet_req __user *)(buf + sz),
				    sizeof(req));
		if (rc) {
			pr_debug("Fail to copy from user buf, pos=%d\n", sz);
			return sz;
		}

		if ((req.flags & SHNET_REQ_SIGNATURE) != SHNET_REQ_SIGNATURE) {
			pr_debug("Invalid message signature 0x%x\n",
				 req.flags & SHNET_REQ_SIGNATURE);
			return sz;
		}

		if ((req.flags & SHNET_REQ_POST_RECV) == SHNET_REQ_POST_RECV)
			rc = shnet_port_recv(file->private_data, &req);

		if ((req.flags & SHNET_REQ_POST_SEND) == SHNET_REQ_POST_SEND)
			rc = snhet_port_send(file->private_data, &req);

		sz += sizeof(req);
	}

out:
	return sz;
}

static const struct file_operations shnet_port_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= shnet_port_ioctl,
	.open		= shnet_port_open,
	.release	= shnet_port_release,
	.read		= shnet_port_read,
	.write		= shnet_port_write,
};

static int shnet_conn_idr_cleanup(int id, void *p, void *data)
{
	kfree((struct shnet_connection *)p);

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
		pr_debug("shnet: unregister device - bad port id %d\n",
			 port->id);
		return -EINVAL;
	}

	list_for_each_entry_safe(port, port2, &shnet_data.ports, list) {
		if (port->id == id) {
			pr_info("Unregistered device on port %d\n", port->id);
			shnet_delete_port(port);
			shnet_destroy_device(port);
			return 0;
		}
	}

	return -ENODEV;
}

static int shnet_register_port(struct shnet_reg *reg)
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
	port->gid.net_id = reg->gid.net_id;
	port->gid.id = reg->gid.id;
	list_add_tail(&port->list, &shnet_data.ports);

	reg->port = id;

	INIT_LIST_HEAD(&port->comps.list);
	mutex_init(&port->comps.lock);
	port->comps.data_flag = 0;
	init_waitqueue_head(&port->comps.queue);

	spin_unlock_irq(&shnet_data.lock);

	mutex_init(&port->conn_mutex);
	idr_init(&port->conn_idr);

	cdev_init(&port->cdev, &shnet_port_ops);
	port->cdev.owner = THIS_MODULE;
	devt = MKDEV(shnet_data.major, id);
	ret = cdev_add(&port->cdev, devt, 1);
	if (ret < 0) {
		pr_debug("Error %d adding cdev for shnet port %d\n", ret, id);
		goto fail_cdev;
	}

	port->dev = device_create(shnet_data.class, NULL, devt, port, "shnet%d",
				  id);
	if (IS_ERR(port->dev)) {
		ret = PTR_ERR(port->dev);
		pr_debug("Error %d creating device for shnet port %d\n", ret,
			 id);
		goto fail_cdev;
	}

	pr_info("Registered device with gid [0x%lx,0x%lx] on port %d major %d\n",
		port->gid.net_id, port->gid.id, port->id,
		shnet_data.major);

	return 0;

fail_cdev:
	cdev_del(&port->cdev);
	shnet_delete_port(port);

fail_port:
	kfree(port);

fail:
	return ret;
}

static long shnet_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret, port;
	struct shnet_reg reg;

	pr_debug("shnet driver ioctl called\n");

	if (_IOC_TYPE(cmd) != SHNET_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > SHNET_IOC_MAX)
		return -ENOTTY;

	switch (cmd) {
	case SHNET_REGISTER_PORT:
		ret = copy_from_user(&reg, (struct shnet_reg __user *)arg,
				     sizeof(reg));
		if (ret)
			return -EFAULT;

		ret = shnet_register_port(&reg);
		if (!ret)
			ret = copy_to_user((struct shnet_reg __user *)arg,
					   &reg, sizeof(reg));

		break;
	case SHNET_UNREGISTER_PORT:
		ret = get_user(port, (int __user *)arg);
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
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= shnet_ioctl,
	.open		= nonseekable_open,
	.release	= shnet_release,
};

static int __init shnet_init(void)
{
	dev_t devt;
	int ret;

	ret = alloc_chrdev_region(&devt, 0, SHNET_MAX_PORTS, "shnet");
	if (ret < 0) {
		pr_debug("Error %d allocating chrdev region for shnet\n", ret);
		return ret;
	}
	shnet_data.major = MAJOR(devt);

	cdev_init(&shnet_data.cdev, &shnet_ops);
	shnet_data.cdev.owner = THIS_MODULE;
	ret = cdev_add(&shnet_data.cdev, devt, 1);
	if (ret < 0) {
		pr_debug("Error %d adding cdev for shnet\n", ret);
		goto fail_chrdev;
	}

	shnet_data.class = class_create(THIS_MODULE, "shnet");
	if (IS_ERR(shnet_data.class)) {
		ret = PTR_ERR(shnet_data.class);
		pr_debug("Error %d creating shnet-class\n", ret);
		goto fail_cdev;
	}

	shnet_data.dev = device_create(shnet_data.class, NULL, devt, NULL,
				       "shnet");
	if (IS_ERR(shnet_data.dev)) {
		ret = PTR_ERR(shnet_data.dev);
		pr_debug("Error %d creating shnet device\n", ret);
		goto fail_class;
	}

	spin_lock_init(&shnet_data.lock);
	INIT_LIST_HEAD(&shnet_data.ports);

	INIT_LIST_HEAD(&global_route);

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
	struct shnet_port *port = NULL, *port2 = NULL;

	list_for_each_entry_safe(port, port2, &shnet_data.ports, list) {
		shnet_delete_port(port);
		shnet_destroy_device(port);
	}

	device_destroy(shnet_data.class, MKDEV(shnet_data.major, 0));
	class_destroy(shnet_data.class);
	cdev_del(&shnet_data.cdev);
	unregister_chrdev_region(MKDEV(shnet_data.major, 0), SHNET_MAX_PORTS);

	pr_info("shnet driver unloaded\n");
} 
EXPORT_SYMBOL_GPL(shnet_exit);

module_init(shnet_init); 
module_exit(shnet_exit);
