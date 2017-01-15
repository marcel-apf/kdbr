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
    ret = ioctl(shnet_fd, SHNET_REGISTER_DEVICE, &port);
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
    ret = ioctl(shnet_fd, SHNET_UNREGISTER_DEVICE, &port);
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

    printf("shnet request received %d\n");

    return 0;
}


int main(int argc, char **argv)
{
    int shnet_fd, port_fd, port, err, opt, sender = 0;
    char shnet_port_name[80] = {0};
    struct shnet_req sreq;
    char buf[20] = {0};
    char buf1[10] = {0};
    char buf2[10] = {0};

    while ((opt = getopt (argc, argv, "s")) != -1) {
        switch (opt) {
        case 's':
            sender = 1;
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

    printf("Opening port %d\n", port);

    sprintf(shnet_port_name, SHNET_FILE_NAME "%d", port);
    port_fd = open(shnet_port_name, 0);
    if (port_fd < 0) {
        err = port_fd;
        printf("Can't open port file: %s%d, error %d\n", SHNET_FILE_NAME, port, errno);
        goto fail_shnet_fd;
    }

    if (sender) {
        strcpy(buf, "Hello world!!!");

        sreq.vec[0].iov_base = buf;
        sreq.vec[0].iov_len = 20;
        sreq.vlen = 1;
    } else {
        struct shnet_req rreq;

        rreq.vec[0].iov_base = buf1;
        rreq.vec[0].iov_len = 10;
        rreq.vec[1].iov_base = buf2;
        rreq.vec[1].iov_len = 10;
        rreq.vlen = 2;

        if (ioctl_recv_req(port_fd, &rreq)) {
            goto fail_port;
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
        printf("Message received %s - %s\n", buf1, buf2);
    }

    close(port_fd);

    if (!ioctl_unregister_device(shnet_fd, port)) {
        printf("shnet device at port %d unregistered\n", port);
    }
    close(shnet_fd);
    printf("shnet fd and port %d closed\n", port);
    return 0;

fail_port:
    close(port_fd);

fail_shnet_fd:
    close(shnet_fd);
    printf("shnet fd closed\n");

    return err;

}

