#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <string.h>
#include <termios.h>
#include <errno.h>

#define __USE_GNU
#include <sys/uio.h>

int main(int argc, char *argv[])
{
    pid_t pid_other = 0;
    struct iovec local[2];
    struct iovec remote[1];
    char dst_buf1[10];
    char dst_buf2[10];
    char src_buf[20] = "Hello World!!!";
    ssize_t nread;


    if (argc > 2) {
        pid_other = atoi(argv[1]);
        remote[0].iov_base = (void *)atol(argv[2]);
        printf("The other is %d, the other buffer address is %lu\n",
               pid_other, (long unsigned int)remote[0].iov_base);
    } else {
        printf("My pid is %d, my buff addr=%lu\n", getpid(), (long unsigned int)src_buf);
        printf("Press Any Key to Continue\n");  
        getchar(); 
        return 0;

    }

    local[0].iov_base = dst_buf1;
    local[0].iov_len = 10;
    local[1].iov_base = dst_buf2;
    local[1].iov_len = 10;

    nread = process_vm_readv(pid_other, local, 2, remote, 1, 0);
    printf("Buffer 1 %s, buffer2 %s\n", dst_buf1, dst_buf2);
    if (nread != 20)
        return 1;

    return 0;
}
 
