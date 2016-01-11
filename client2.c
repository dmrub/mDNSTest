#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dns_sd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int set_nonblocking(int fd)
{
    int flags;
    /* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
    /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
    /* Otherwise, use the old way of doing it */
    flags = 1;
    return ioctl(fd, FIOBIO, &flags);
#endif
}     

void cb(DNSServiceRef sdRef,
        DNSServiceFlags flags,
        uint32_t interfaceIndex,
        DNSServiceErrorType errorCode,
        const char *serviceName,
        const char *regtype,
        const char *replyDomain,
        void *context) {
    printf("called %s %s!\n", serviceName, regtype);
}

int main() {
    DNSServiceRef sd = malloc(sizeof(DNSServiceRef));
    const char *regtype = "_http._tcp";
    DNSServiceErrorType err1 = DNSServiceBrowse(&sd, 0, 0, regtype, NULL, &cb, NULL);
    printf("err1=%d\n", err1);
    int socket = DNSServiceRefSockFD(sd);
    set_nonblocking(socket);

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(socket, &read_fds);

    while(1) {
        if(select(socket+1, &read_fds, NULL, NULL, NULL)  < 0) {
            perror("select");  
        }
        DNSServiceErrorType err2 = DNSServiceProcessResult(sd);
        printf("err2=%d\n", err2);
        if(err2 != 0)
            return 2;
    }
    return 0;
}
