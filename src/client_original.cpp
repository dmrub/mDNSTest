#include <dns_sd.h>
#include <iostream>

using namespace std;

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
    int s = DNSServiceRefSockFD(*sdRef);
    while (1)
    {
        DNSServiceProcessResult(*sdRef);
    }
    DNSServiceRefDeallocate(*sdRef);
    return 0;
}
