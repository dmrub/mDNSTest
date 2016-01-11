#include <dns_sd.h>
#include <iostream>

#include <fcntl.h>
#include <cstdio>

using namespace std;

// AVAHI
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


/**************************************************************************************
 *
 **************************************************************************************/
void resolveReply (
    DNSServiceRef sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    DNSServiceErrorType errorCode,
    const char *fullname,
    const char *hosttarget,
    uint16_t port, /* In network byte order */
    uint16_t txtLen,
    const unsigned char *txtRecord,
    void *context )
{
    std::cout << "Resolved: "
              << fullname << " : " << hosttarget << " : " << port << endl
              << "txtlng: " << txtLen << " : " << txtRecord << endl;
    return;
}

/**************************************************************************************
 *
 **************************************************************************************/
void browseReply (
    DNSServiceRef sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    DNSServiceErrorType errorCode,
    const char *serviceName,
    const char *regtype,
    const char *replyDomain,
    void *context )
{
    cout << "Service: " << serviceName << " : " << regtype << " : " << replyDomain << endl;
    DNSServiceRef *sdRRef = new DNSServiceRef;
    //DNSServiceFlags flags;
    DNSServiceErrorType error = DNSServiceResolve ( sdRRef,
                                flags,
                                interfaceIndex,
                                serviceName,
                                regtype,
                                replyDomain,
                                resolveReply,
                                context);
    DNSServiceProcessResult(*sdRRef);
    return;
}

/**************************************************************************************
 *
 **************************************************************************************/
int main(int argc, char** argv)
{
    DNSServiceRef *sdRef = new DNSServiceRef;
    DNSServiceFlags flags = 0;
    uint32_t interfaceIndex = 0;
    const char *regtype = "_http._tcp";
    DNSServiceErrorType error = DNSServiceBrowse( sdRef,
                                flags,
                                interfaceIndex,
                                regtype,
                                NULL/*"local"*/,
                                &browseReply,
                                NULL);
    if (error != kDNSServiceErr_NoError)
        std::cout << "We had some error! Take all i know!!"<<std::endl;
    else
        std::cout << "No error" << std::endl;
    int socket = DNSServiceRefSockFD(*sdRef);

    set_nonblocking(socket);
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(socket, &read_fds);

    while (1)
    {
        if(select(socket+1, &read_fds, NULL, NULL, NULL)  < 0)
        {
            perror("select");
        }

        DNSServiceErrorType err2 = DNSServiceProcessResult(*sdRef);
        std::cerr<<"err2=" << err2 << std::endl;
        if (err2 != 0)
            return 2;
    }
    DNSServiceRefDeallocate(*sdRef);
    return 0;
}
