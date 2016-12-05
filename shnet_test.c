#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <string.h>
#include <termios.h>
#include <errno.h>

#define SHNET_FILE_NAME "/dev/shnet"

#define SHNET_IOC_MAGIC 0xBA
#define SHNET_REGISTER_DEVICE _IOR(SHNET_IOC_MAGIC, 0, int)

int ioctl_register_device(int shnet_fd)
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



int main(void)
{
    int shnet_fd, port_fd, port, err;
    char shnet_port_name[80] = {0};

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

    printf("Press Any Key to Continue\n");  
    getchar();  

    close(port_fd);
    close(shnet_fd);
    printf("shnet fd and port %d closed\n", port);
    return 0;


fail_shnet_fd:
    close(shnet_fd);
    printf("shnet fd closed\n");

    return err;

}

