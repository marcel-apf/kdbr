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

static int ioctl_register_device(int kdbr_fd, struct kdbr_reg *reg)
{
    int ret;

    printf("kdbr register device\n");
    ret = ioctl(kdbr_fd, KDBR_REGISTER_PORT, reg);
    if (ret == -1) {
        fprintf(stderr, "KDBR_REGISTER_DEVICE failed: %s\n", strerror(ret));
        return ret;
    }

    printf("kdbr device with gid %ld registered to port %d\n",
	   reg->gid.id, reg->port);

    return reg->port;
}

static int ioctl_unregister_device(int kdbr_fd, int port)
{
    int ret;

    printf("kdbr unregister device at port %d\n", port);
    ret = ioctl(kdbr_fd, KDBR_UNREGISTER_PORT, &port);
    if (ret == -1) {
        fprintf(stderr, "KDBR_UNREGISTER_DEVICE failed: %s\n", strerror(ret));
    }

    return ret;
}

static int ioctl_open_conn(int port_fd, struct kdbr_connection *conn)
{
    int ret;

    ret = ioctl(port_fd, KDBR_PORT_OPEN_CONN, conn);
    if (ret == -1) {
        fprintf(stderr, "KDBR_PORT_OPEN_CONN failed: %s\n", strerror(ret));
        return ret;
    }

    printf("kdbr opened connection %d\n", ret);

    return ret;
}

static int ioctl_close_conn(int port_fd, int conn_id)
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
    int kdbr_fd, port_fd, port, err, opt, r_id, conn_id, sender = 0;
    char kdbr_port_name[80] = {0};
    struct kdbr_req sreq;
    struct kdbr_connection conn = {0};
    struct kdbr_reg reg = {0};
    char *buf = malloc(20);
    char *buf1 = malloc(10);
    char *buf2 = malloc(10);

    while ((opt = getopt (argc, argv, "sr:g:")) != -1) {
        switch (opt) {
        case 's':
            sender = 1;
            break;
        case 'r':
            r_id = atoi(optarg);
            break;
	case 'g':
	    reg.gid.id = atoi(optarg);
	    break;
        default:
            exit(1);
        }
    }

    kdbr_fd = open(KDBR_FILE_NAME, 0);
    if (kdbr_fd < 0) {
        printf("Can't open device file: %s\n", KDBR_FILE_NAME);
        exit(-1);
    }

    printf("kdbr fd opened\n");
    port = ioctl_register_device(kdbr_fd, &reg);
    if (port <= 0) {
        err = port;
        printf("Can't open device file: %s\n", KDBR_FILE_NAME);
        goto fail_kdbr_fd;
    }

    printf("Opening port %d, pid %d\n", port, getpid());

    sprintf(kdbr_port_name, KDBR_FILE_NAME "%d", port);
    port_fd = open(kdbr_port_name, O_RDWR);
    if (port_fd < 0) {
        err = port_fd;
        printf("Can't open port file: %s%d, error %d\n", KDBR_FILE_NAME, port, errno);
        goto fail_kdbr_fd;
    }

    conn_id = ioctl_open_conn(port_fd, &conn);
    if (conn_id < 0)
        goto fail_port;

    if (sender) {
        strcpy(buf, "Hello world!!!");

        sreq.vec[0].iov_base = buf;
        sreq.vec[0].iov_len = 20;
        sreq.vlen = 1;
    } else {
        struct kdbr_req rreq;

        /*
        rreq.vec[0].iov_base = buf2;
        rreq.vec[0].iov_len = 10;
        rreq.vec[1].iov_base = buf1;
        rreq.vec[1].iov_len = 10;
        rreq.vlen = 2;
        */
        rreq.vec[0].iov_base = buf;
        rreq.vec[0].iov_len = 20;
        rreq.vlen = 1;

	rreq.flags = KDBR_REQ_SIGNATURE | KDBR_REQ_POST_RECV;
	err = write(port_fd, &rreq, sizeof(rreq));
	if (err < 0) {
		printf("write: err=%d, errno=%d\n", err, errno);
		goto fail_conn;
	}
    }

    printf("Ready - Press Any Key to Continue\n");
    getchar();

    if (sender) {
	sreq.flags = KDBR_REQ_SIGNATURE | KDBR_REQ_POST_SEND;
	err = write(port_fd, &sreq, sizeof(sreq));
	if (err < 0) {
		printf("write: err=%d, errno=%d\n", err, errno);
		goto fail_conn;
	}
        printf("Message sent - Press Any Key to Continue\n");
        getchar();
    } else {
        printf("Message received buf='%s'\n", buf);
        printf("Message received buf1='%s'\n", buf1);
        printf("Message received buf2='%s'\n", buf2);
    }

    ioctl_close_conn(port_fd, conn_id);
    close(port_fd);

    if (!ioctl_unregister_device(kdbr_fd, port)) {
        printf("kdbr device at port %d unregistered\n", port);
    }
    close(kdbr_fd);
    printf("kdbr fd and port %d closed\n", port);
    err = 0;
    goto out;

fail_conn:
    ioctl_close_conn(port_fd, conn_id);

fail_port:
    close(port_fd);

fail_kdbr_fd:
    close(kdbr_fd);
    printf("kdbr fd closed\n");

out:
    free(buf2);
    free(buf1);
    free(buf);
    return err;

}

