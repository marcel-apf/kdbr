/*
 * Kernel-based shared networking driver - API
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

#ifndef _SHNET_H
#define _SHNET_H

#ifdef __KERNEL__
#include <linux/uio.h>
#define SHNET_MAX_IOVEC_LEN	UIO_FASTIOV
#else
#include <sys/uio.h>
#define SHNET_MAX_IOVEC_LEN	8
#endif

#define SHNET_FILE_NAME "/dev/shnet"
#define SHNET_MAX_PORTS 255

#define SHNET_IOC_MAGIC 0xBA

#define SHNET_REGISTER_PORT	_IOWR(SHNET_IOC_MAGIC, 0, struct shnet_reg)
#define SHNET_UNREGISTER_PORT	_IOW(SHNET_IOC_MAGIC, 1, int)
#define SHNET_IOC_MAX		2


enum shnet_ack_type {
	SHNET_ACK_IMMEDIATE,
	SHNET_ACK_DELAYED,
};

struct shnet_gid {
	unsigned long net_id;
	unsigned long id;
};

struct shnet_peer {
	struct shnet_gid rgid;
	unsigned long rqueue;
};

struct list_head;
struct shnet_connection {
	unsigned long queue_id;
	struct shnet_peer peer;
	enum shnet_ack_type ack_type;
	struct list_head *sg_vecs_list;
};

struct shnet_reg {
	struct shnet_gid gid; /* in */
	int port; /* out */
};

#define SHNET_REQ_SIGNATURE	0x000000AB
#define SHNET_REQ_POST_RECV	0x00000100
#define SHNET_REQ_POST_SEND	0x00000200
#define SHNET_REQ_POST_MREG	0x00000300
#define SHNET_REQ_POST_RDMA	0x00000400

struct shnet_req {
	unsigned int flags; /* 8 bits signature, 8 bits msg_type */
	struct iovec vec[SHNET_MAX_IOVEC_LEN];
	int vlen; /* <= SHNET_MAX_IOVEC_LEN */
	int connection_id;
	struct shnet_peer peer;
	unsigned long req_id;
};

#define SHNET_ERR_CODE_EMPTY_VEC	0x101
#define SHNET_ERR_CODE_NO_MORE_RECV_BUF	0x102
#define SHNET_ERR_CODE_RECV_BUF_PROT	0x103
#define SHNET_ERR_CODE_INV_ADDR		0x104
#define SHNET_ERR_CODE_INV_CONN_ID	0x105
#define SHNET_ERR_CODE_NO_PEER		0x106

struct shnet_completion {
	int connection_id;
	unsigned long req_id;
	int status; /* 0 = Success */
};

#define SHNET_PORT_IOC_MAGIC 0xBB

#define SHNET_PORT_OPEN_CONN	_IOR(SHNET_PORT_IOC_MAGIC, 0, \
				     struct shnet_connection)
#define SHNET_PORT_CLOSE_CONN	_IOR(SHNET_PORT_IOC_MAGIC, 1, int)
#define SHNET_PORT_IOC_MAX	4

#endif

