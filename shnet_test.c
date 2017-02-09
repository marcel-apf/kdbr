#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include "shnet.h"

static int ioctl_register_device(int shnet_fd)
{
    int port, ret;

    printf("shnet register device\n");
    ret = ioctl(shnet_fd, SHNET_REGISTER_PORT, &port);
    if (ret == -1) {
        fprintf(stderr, "SHNET_REGISTER_DEVICE failed: %s\n", strerror(ret));
        return ret;
    }

    printf("shnet device registered to port %d\n", port);

    return port;
}

static int ioctl_unregister_device(int shnet_fd, int port)
{
    int ret;

    printf("shnet unregister device at port %d\n", port);
    ret = ioctl(shnet_fd, SHNET_UNREGISTER_PORT, &port);
    if (ret == -1) {
        fprintf(stderr, "SHNET_UNREGISTER_DEVICE failed: %s\n", strerror(ret));
    }

    return ret;
}

static int ioctl_send_req(int port_fd, struct shnet_req *req)
{
    int ret;

    ret = ioctl(port_fd, SHNET_PORT_SEND, req);
    if (ret == -1) {
        fprintf(stderr, "SHNET_PORT_SEND failed: %s\n", strerror(ret));
        return ret;
    }

    printf("shnet request sent\n");

    return 0;
}

static int ioctl_recv_req(int port_fd, struct shnet_req *req)
{
    int ret;

    ret = ioctl(port_fd, SHNET_PORT_RECV, req);
    if (ret == -1) {
        fprintf(stderr, "SHNET_PORT_SEND failed: %s\n", strerror(ret));
        return ret;
    }

    printf("shnet request received\n");

    return 0;
}

static int ioctl_open_conn(int port_fd, struct shnet_connection *conn)
{
    int ret;

    ret = ioctl(port_fd, SHNET_PORT_OPEN_CONN, conn);
    if (ret == -1) {
        fprintf(stderr, "SHNET_PORT_OPEN_CONN failed: %s\n", strerror(ret));
        return ret;
    }

    printf("shnet opened connection %d\n", ret);

    return ret;
}

static int ioctl_close_conn(int port_fd, int conn_id)
{
    int ret;

    ret = ioctl(port_fd, SHNET_PORT_CLOSE_CONN, conn_id);
    if (ret == -1) {
        fprintf(stderr, "SHNET_PORT_CLOSE_CONN failed: %s\n", strerror(ret));
        return ret;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int shnet_fd, port_fd, port, err, opt, r_id, conn_id, sender = 0;
    char shnet_port_name[80] = {0};
    struct shnet_req sreq;
    struct shnet_connection conn = {0};
    
    char *buf = aligned_alloc(4096, 20);
    //char *buf = malloc(20);
    char *buf1 = aligned_alloc(4096, 10);
    char *buf2 = aligned_alloc(4096, 10);

    while ((opt = getopt (argc, argv, "sr:")) != -1) {
        switch (opt) {
        case 's':
            sender = 1;
            break;
        case 'r':
            r_id = atoi(optarg);
            break;
        default:
            exit(1);
        }
    }

    shnet_fd = open(SHNET_FILE_NAME, 0);
    if (shnet_fd < 0) {
        printf("Can't open device file: %s\n", SHNET_FILE_NAME);
        exit(-1);
    }

    printf("shnet fd opened\n");
    port = ioctl_register_device(shnet_fd);
    if (port <= 0) {
        err = port;
        printf("Can't open device file: %s\n", SHNET_FILE_NAME);
        goto fail_shnet_fd;
    }

    printf("Opening port %d, pid %d\n", port, getpid());

    sprintf(shnet_port_name, SHNET_FILE_NAME "%d", port);
    port_fd = open(shnet_port_name, 0);
    if (port_fd < 0) {
        err = port_fd;
        printf("Can't open port file: %s%d, error %d\n", SHNET_FILE_NAME, port, errno);
        goto fail_shnet_fd;
    }

    conn_id = ioctl_open_conn(port_fd, &conn);
    if (conn_id < 0) {
        goto fail_port;
    }

    if (sender) {
        strcpy(buf, "Hello world!!!");

        sreq.vec[0].iov_base = buf;
        sreq.vec[0].iov_len = 20;
        sreq.vlen = 1;
    } else {
        struct shnet_req rreq;

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

        if (ioctl_recv_req(port_fd, &rreq)) {
            goto fail_conn;
        }
    }

    printf("Ready - Press Any Key to Continue\n");
    getchar();

    if (sender) {
        if (!ioctl_send_req(port_fd, &sreq)) {
            printf("Message sent - Press Any Key to Continue\n");
            getchar();
        }
    } else {
        printf("Message received buf='%s'\n", buf);
        printf("Message received buf1='%s'\n", buf1);
        printf("Message received buf2='%s'\n", buf2);
    }

    ioctl_close_conn(port_fd, conn_id);
    close(port_fd);

    if (!ioctl_unregister_device(shnet_fd, port)) {
        printf("shnet device at port %d unregistered\n", port);
    }
    close(shnet_fd);
    printf("shnet fd and port %d closed\n", port);
    err = 0;
    goto out;

fail_conn:
    ioctl_close_conn(port_fd, conn_id);

fail_port:
    close(port_fd);

fail_shnet_fd:
    close(shnet_fd);
    printf("shnet fd closed\n");

out:
    free(buf2);
    free(buf1);
    free(buf);
    return err;

}

