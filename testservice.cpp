#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")
    #pragma comment(lib, "dnssd.lib")
#else
#include <arpa/inet.h>
#endif
#include <stdint.h>
#include <dns_sd.h>
#include <iostream>
#include <cstring>

extern "C" void DNSSD_API DNSSDRegisterCallback(
    DNSServiceRef                       sdRef,
    DNSServiceFlags                     flags,
    DNSServiceErrorType                 errorCode,
    const char                          *name,
    const char                          *regtype,
    const char                          *domain,
    void                                *context
    )
{
    // This is the asynchronous callback
    // Can be used to handle async. errors, get data from instantiated service or record references, etc.
    // Context is same pointer that was given to the callout
    // If registration was successful, errorCode = kDNSServiceErr_NoError
}

int main(int argc, char *argv[])
{

    std::cout << "Registering DNSService...";
    DNSServiceRef sdRef; // Uninitialized reference to service
    DNSServiceFlags flags = 0;
    uint32_t interfaceIndex = 0; // 0 means try to register on all available interfaces
    // service name setup
    const char *name = "ARVIDA Service 1"; // service name
    const char *regtype = "_http._tcp"; // service type
    const char *domain = "local"; // service domain
    char *host = 0; // null means use the computer's default host name
    // service name setup done
    uint16_t port = htons(8080); // network byte order of 8080

    const char *relPath = "\x0fpath=/mywebsite";
    uint16_t txtLen = strlen(relPath)+1; // TXTrecord is NULL
    const void *txtRecord = relPath; // NULL

    void *context = 0; // context pointer to data to be passed to callback

    DNSServiceErrorType errorCode =
        DNSServiceRegister(&sdRef,
                           flags,
                           interfaceIndex,
                           name,
                           regtype,
                           domain,
                           host,
                           port,
                           txtLen,
                           txtRecord,
                           DNSSDRegisterCallback, // callback pointer, called upon return from API
                           context);
    std::cin.get();
}
