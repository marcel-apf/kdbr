#ifndef _SHNET_H
#define _SHNET_H
/*
 * Kernel-based shared networking driver - API
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

#include <linux/uio.h>

#define SHNET_MAX_PORTS 255

#define SHNET_IOC_MAGIC 0xBA

#define SHNET_REGISTER_DEVICE       _IOR(SHNET_IOC_MAGIC, 0, int)
#define SHNET_UNREGISTER_DEVICE     _IOW(SHNET_IOC_MAGIC, 1, int)
#define SHNET_IOC_MAX               2

#define SHNET_MAX_IOVEC_LEN        UIO_FASTIOV

struct shnet_send_req {
    unsigned long req_id;
    struct iovec vec[SHNET_MAX_IOVEC_LEN];
    int vlen; /* <= SHNET_MAX_IOVEC_LEN */
    int dst_id;
};

struct shnet_recv_req {
    unsigned long req_id;
    struct iovec vec[SHNET_MAX_IOVEC_LEN];
    int vlen; /* <= SHNET_MAX_IOVEC_LEN */
};

#define SHNET_PORT_IOC_MAGIC 0xBB

#define SHNET_PORT_RECV    _IOR(SHNET_PORT_IOC_MAGIC, 0, struct shnet_recv_req)
#define SHNET_PORT_SEND    _IOW(SHNET_PORT_IOC_MAGIC, 1, struct shnet_send_req)
#define SHNET_PORT_IOC_MAX 2

#endif

