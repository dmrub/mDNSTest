#include <dns_sd.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

void DNSSDRegisterCallback(DNSServiceRef sdRef,
                           DNSServiceFlags flags,
                           DNSServiceErrorType errorCode,
                           const char *name,
                           const char *regtype,
                           const char *domain,
                           void *context )
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
    char *name = "ARVIDA Service 1"; // service name
    char *regtype = "_http._tcp"; // service type
    char *domain = "local"; // service domain
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
