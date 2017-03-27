#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include "kdbr.h"

static int register_port(int kdbr_fd, struct kdbr_reg *reg)
{
    int ret;

    printf("Registering port net_id 0x%lx, id 0x%lx\n", reg->gid.net_id,
           reg->gid.id);
    ret = ioctl(kdbr_fd, KDBR_REGISTER_PORT, reg);
    if (ret == -1) {
        fprintf(stderr, "KDBR_REGISTER_DEVICE failed: %s\n", strerror(ret));
        return ret;
    }

    printf("Registered to kdbr port %d\n", reg->port);

    return 0;
}

static int unregister_port(int kdbr_fd, int port)
{
    int ret;

    printf("kdbr unregister port at port %d\n", port);
    ret = ioctl(kdbr_fd, KDBR_UNREGISTER_PORT, &port);
    if (ret == -1)
        fprintf(stderr, "KDBR_UNREGISTER_DEVICE failed: %s\n", strerror(ret));

    return ret;
}

static int connect(int port_fd, struct kdbr_connection *conn)
{
    int ret;

    printf("Connecting to net_id 0x%lx, id 0x%lx, queue 0x%lx\n",
           conn->peer.rgid.net_id, conn->peer.rgid.id, conn->peer.rqueue);

    ret = ioctl(port_fd, KDBR_PORT_OPEN_CONN, conn);
    if (ret == -1) {
        fprintf(stderr, "KDBR_PORT_OPEN_CONN failed: %s\n", strerror(ret));
        return ret;
    }

    printf("Connected (conn_id %d)\n", ret);

    return ret;
}

static int disconnect(int port_fd, int conn_id)
{
    int ret;

    ret = ioctl(port_fd, KDBR_PORT_CLOSE_CONN, &conn_id);
    if (ret == -1) {
        fprintf(stderr, "KDBR_PORT_CLOSE_CONN failed: conn %d %s\n",
		conn_id, strerror(ret));
        return ret;
    }

    printf("kdbr closed connection %d\n", conn_id);
    return 0;
}

int main(int argc, char **argv)
{
    int kdbr_fd, port_fd, err, conn_id, opt, sender = 0;
    char kdbr_port_name[80] = {0};
    struct kdbr_req sreq;
    struct kdbr_connection conn = {0};
    struct kdbr_reg reg = {0};
    char *buf = malloc(20);

    /* Open kdbr device file */
    kdbr_fd = open(KDBR_FILE_NAME, 0);
    if (kdbr_fd < 0) {
        printf("Can't open device file: %s\n", KDBR_FILE_NAME);
        exit(-1);
    }
    printf("kdbr fd opened\n");

    while ((opt = getopt (argc, argv, "sg:p:q:r:")) != -1) {
        switch (opt) {
        case 's':  /* sender */
            sender = 1;
            break;
	case 'g':  /* gid */
	    reg.gid.id = atoi(optarg);
	    break;
	case 'p': /* remote gid */
	    conn.peer.rgid.id = atoi(optarg);
	    break;
	case 'q':   /* queue id */
            conn.queue_id = atoi(optarg);
	    break;
	case 'r':  /* remote queue id */
	    conn.peer.rqueue = atoi(optarg);
	    break;
        default:
            exit(1);
        }
    }

    /* Register our port (net_id and id) */
    err = register_port(kdbr_fd, &reg);
    if (err)
        goto fail_kdbr_fd;

    /* Open the new port's device file */
    sprintf(kdbr_port_name, KDBR_FILE_NAME "%d", reg.port);
    port_fd = open(kdbr_port_name, O_RDWR);
    if (port_fd < 0) {
        err = port_fd;
        printf("Can't open port file: %s%d, error %d\n", KDBR_FILE_NAME,
               reg.port, errno);
        goto fail_kdbr_fd;
    }

    /* Connect to peer */
    conn_id = connect(port_fd, &conn);
    if (conn_id < 0)
        goto fail_port;

    if (!sender) {
        /* Register buffer for receive  */
        struct kdbr_req rreq;

        rreq.vec[0].iov_base = buf;
        rreq.vec[0].iov_len = 20;
        rreq.vlen = 1;
	rreq.connection_id = conn_id;

	rreq.flags = KDBR_REQ_SIGNATURE | KDBR_REQ_POST_RECV;
	err = write(port_fd, &rreq, sizeof(rreq));
	if (err < 0) {
		printf("write: err=%d, errno=%d\n", err, errno);
		goto fail_conn;
	}
        printf("Buffer registered, press any key to continue\n");
        getchar();
        printf("Message received buf='%s'\n", buf);
    } else {
        /* Send buffer to peer */
        strcpy(buf, "Hello world!!!");
        sreq.vec[0].iov_base = buf;
        sreq.vec[0].iov_len = 20;
        sreq.vlen = 1;
	sreq.flags = KDBR_REQ_SIGNATURE | KDBR_REQ_POST_SEND;
	sreq.connection_id = conn_id;
        printf("Press any key to send message\n");
        getchar();
	err = write(port_fd, &sreq, sizeof(sreq));
	if (err < 0) {
		printf("write: err=%d, errno=%d\n", err, errno);
		goto fail_conn;
	}
    }

    disconnect(port_fd, conn_id);
    close(port_fd);

    unregister_port(kdbr_fd, reg.port);
    close(kdbr_fd);
    printf("kdbr fd and port %d closed\n", reg.port);
    err = 0;
    goto out;

fail_conn:
    disconnect(port_fd, conn_id);

fail_port:
    close(port_fd);

fail_kdbr_fd:
    close(kdbr_fd);
    printf("kdbr fd closed\n");

out:
    free(buf);
    return err;

}

