/*
 * BonjourMDNSManager.cpp
 *
 *  Created on: Jan 15, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"

#ifdef _WIN32
#include <process.h>
typedef int pid_t;
#define getpid _getpid
#define strcasecmp _stricmp
#define snprintf _snprintf
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "dnssd.lib")
#else
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include <dns_sd.h>
#include <thread>
#include <mutex>
#include <atomic>

#include <cerrno>
#include <cstring>
#include <cstddef>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <iostream>

namespace MDNS
{

namespace
{

inline uint32_t toDnsSdInterfaceIndex(MDNSInterfaceIndex i)
{
    if (i == MDNS_IF_ANY)
    {
        return kDNSServiceInterfaceIndexAny;
    }
    return static_cast<uint32_t>(i);
}

inline MDNSInterfaceIndex fromDnsSdInterfaceIndex(uint32_t i)
{
    if (i == kDNSServiceInterfaceIndexAny)
    {
        return MDNS_IF_ANY;
    }
    return static_cast<MDNSInterfaceIndex>(i);
}


inline const char * toDnsSdStr(const std::string & str)
{
    return str.empty() ? 0 : str.c_str();
}

inline std::string fromDnsSdStr(const char *str)
{
    return str ? str : "";
}

std::string encodeTxtRecordData(const std::vector<std::string> & fields, bool & invalidFields)
{
    std::string str;
    invalidFields = false;

    for (auto it = fields.begin(), iend = fields.end(); it != iend; ++it)
    {
        if (it->length() > 255)
        {
            invalidFields = true;
            continue;
        }
        if (it->find_first_of('\0', 0) != std::string::npos)
        {
            invalidFields = true;
            continue;
        }

        str += (char)it->length();
        str += *it;
    }

    return str;
}

const char * getDnsSdErrorName(DNSServiceErrorType error)
{
    switch (error)
    {
        case kDNSServiceErr_NoError: return "kDNSServiceErr_NoError";
        case kDNSServiceErr_Unknown: return "kDNSServiceErr_Unknown";
        case kDNSServiceErr_NoSuchName: return "kDNSServiceErr_NoSuchName";
        case kDNSServiceErr_NoMemory: return "kDNSServiceErr_NoMemory";
        case kDNSServiceErr_BadParam: return "kDNSServiceErr_BadParam";
        case kDNSServiceErr_BadReference: return "kDNSServiceErr_BadReference";
        case kDNSServiceErr_BadState: return "kDNSServiceErr_BadState";
        case kDNSServiceErr_BadFlags: return "kDNSServiceErr_BadFlags";
        case kDNSServiceErr_Unsupported: return "kDNSServiceErr_Unsupported";
        case kDNSServiceErr_NotInitialized: return "kDNSServiceErr_NotInitialized";
        case kDNSServiceErr_AlreadyRegistered: return "kDNSServiceErr_AlreadyRegistered";
        case kDNSServiceErr_NameConflict: return "kDNSServiceErr_NameConflict";
        case kDNSServiceErr_Invalid: return "kDNSServiceErr_Invalid";
        case kDNSServiceErr_Firewall: return "kDNSServiceErr_Firewall";
        case kDNSServiceErr_Incompatible: return "kDNSServiceErr_Incompatible";
        case kDNSServiceErr_BadInterfaceIndex: return "kDNSServiceErr_BadInterfaceIndex";
        case kDNSServiceErr_Refused: return "kDNSServiceErr_Refused";
        case kDNSServiceErr_NoSuchRecord: return "kDNSServiceErr_NoSuchRecord";
        case kDNSServiceErr_NoAuth: return "kDNSServiceErr_NoAuth";
        case kDNSServiceErr_NoSuchKey: return "kDNSServiceErr_NoSuchKey";
        case kDNSServiceErr_NATTraversal: return "kDNSServiceErr_NATTraversal";
        case kDNSServiceErr_DoubleNAT: return "kDNSServiceErr_DoubleNAT";
        case kDNSServiceErr_BadTime: return "kDNSServiceErr_BadTime";
        default: return "Unknown";
    }
}

class DnsSdError: public std::runtime_error
{
public:

    DnsSdError(const std::string &message)
        : std::runtime_error(message)
    {
    }

    virtual ~DnsSdError() noexcept
    {
    }
};

#if 0

class AvahiClientError: public AvahiError
{
public:
    AvahiClientError(const std::string & reason, AvahiClient * client)
        : AvahiError(formatError(reason, client))
        , error_(avahi_client_errno(client))
    {
    }

    AvahiClientError(const std::string & reason, int error)
        : AvahiError(formatError(reason, error))
        , error_(error)
    {
    }

    virtual ~AvahiClientError() noexcept
    {
    }

    int error()
    {
        return error_;
    }

    static std::string formatError(const std::string & what, AvahiClient *client)
    {
        return formatError(what, avahi_client_errno(client));
    }

    static std::string formatError(const std::string & what, int error)
    {
        std::ostringstream os;
        os << what << " error " << error << ": " << avahi_strerror(error);
        return os.str();
    }

private:
    int error_;
};
#endif

template <class T>
class FlagGuard
{
public:

    FlagGuard(T &flag)
        : flag_(flag)
    {
        flag_ = true;
    }

    ~FlagGuard()
    {
        flag_ = false;
    }

private:
    T &flag_;
};


} // unnamed namespace

class MDNSManager::PImpl
{
public:

    std::thread thread;
    std::mutex mutex;
    std::atomic<bool> processEvents;
    std::vector<DNSServiceRef> serviceRefs;

    MDNSManager::AlternativeServiceNameHandler alternativeServiceNameHandler;
    MDNSManager::ErrorHandler errorHandler;
    std::vector<std::string> errorLog;

    PImpl()
        : thread(), mutex(), processEvents(true)
    {
    }

    ~PImpl()
    {
        stop();
    }

    void eventLoop()
    {
        std::vector<DNSServiceRef> localRefs;
        while (processEvents)
        {

            {
                std::lock_guard<std::mutex> g(mutex);
                localRefs = serviceRefs;
            }

            int maxFD = 0;
            fd_set readfds;
            fd_set* nullFd = (fd_set*) 0;

            for (auto it = localRefs.begin(), iend = localRefs.end(); it != iend; ++it)
            {
                int fd  = DNSServiceRefSockFD(*it);
                if (maxFD < fd)
                    maxFD = fd;

                // 2. Add the fd to the fd_set
                FD_SET(fd , &readfds);


                // handleEvents(*it);
            }

            int nfds = maxFD + 1;

            // 3. Set up the timeout.
            struct timeval tv;
            tv.tv_sec = 1; // wakes up every 1 sec if no socket activity occurs
            tv.tv_usec = 0;

            // wait for pending data or 5 secs to elapse:
            int result = select(nfds, &readfds, nullFd, nullFd, &tv);
            if (result > 0)
            {
                for (auto it = localRefs.begin(), iend = localRefs.end(); it != iend; ++it)
                {
                    int fd = DNSServiceRefSockFD(*it);
                    if (FD_ISSET(fd , &readfds))
                    {
                        DNSServiceErrorType err = DNSServiceProcessResult(*it);
                        if (err != kDNSServiceErr_NoError)
                        {
                            fprintf(stderr,
                                "DNSServiceProcessResult returned %d\n", err);
                        }
                    }
                }
            }
            else if (result == 0)
            {
                // timeout elapsed but no fd-s were signalled.
            }
            else
            {
                printf("select() returned %d errno %d %s\n",
                    result, errno, strerror(errno));
            }

            std::this_thread::yield();
        }
    }

    static void handleEvents(DNSServiceRef serviceRef)
    {
        int fd  = DNSServiceRefSockFD(serviceRef);
        int nfds = fd + 1;
        fd_set readfds;
        fd_set* nullFd = (fd_set*) 0;
        struct timeval tv;
        int result;
        bool stopNow = false;

        while (!stopNow)
        {
            // 1. Set up the fd_set as usual here.
            FD_ZERO(&readfds);

            // 2. Add the fd to the fd_set
            FD_SET(fd , &readfds);

            // 3. Set up the timeout.
            tv.tv_sec = 1; // wakes up every 5 sec if no socket activity occurs
            tv.tv_usec = 0;

            // wait for pending data or 5 secs to elapse:
            result = select(nfds, &readfds, nullFd, nullFd, &tv);
            if (result > 0)
            {
                DNSServiceErrorType err = kDNSServiceErr_NoError;
                if (FD_ISSET(fd , &readfds))
                {
                    err = DNSServiceProcessResult(serviceRef);
                }
                if (err != kDNSServiceErr_NoError)
                {
                    fprintf(stderr,
                        "DNSServiceProcessResult returned %d\n", err);
                    stopNow = true;
                }
            }
            else if (result == 0)
            {
                // timeout elapsed but no fd-s were signalled.
            }
            else
            {
                printf("select() returned %d errno %d %s\n",
                    result, errno, strerror(errno));
                stopNow = (errno != EINTR);
            }
        }
    }

    void run()
    {
        if (thread.joinable())
        {
            throw std::logic_error("MDNSManager already running");
        }
        processEvents = true;
        thread = std::move(std::thread(&PImpl::eventLoop, this));
    }

    void stop()
    {
        if (!thread.joinable())
        {
            throw std::logic_error("MDNSManager is not running");
        }
        processEvents = false;
        thread.join();
    }

    void error(std::string errorMsg)
    {
        if (errorHandler)
            errorHandler(errorMsg);
        errorLog.push_back(std::move(errorMsg));
    }

    static void DNSSD_API registerCallback(
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
        MDNSManager::PImpl *self = static_cast<MDNSManager::PImpl*>(context);
        std::cerr<<"REGISTER CALLBACK "<<name<<std::endl;
    }

    void addServiceRef(DNSServiceRef serviceRef)
    {
        std::lock_guard<std::mutex> g(mutex);
        serviceRefs.push_back(serviceRef);
    }

};

MDNSManager::MDNSManager()
    : pimpl_(new MDNSManager::PImpl)
{
}

MDNSManager::~MDNSManager()
{
}

bool MDNSManager::isAvailable()
{
    return true;
}

void MDNSManager::run()
{
    pimpl_->run();
}

void MDNSManager::stop()
{
    pimpl_->stop();
}

void MDNSManager::setAlternativeServiceNameHandler(MDNSManager::AlternativeServiceNameHandler handler)
{
    std::lock_guard<std::mutex> g(pimpl_->mutex);
    pimpl_->alternativeServiceNameHandler = handler;
}

void MDNSManager::setErrorHandler(MDNSManager::ErrorHandler handler)
{
    std::lock_guard<std::mutex> g(pimpl_->mutex);
    pimpl_->errorHandler = handler;
}

void MDNSManager::registerService(MDNSService service)
{
    DNSServiceRef sdRef; // Uninitialized reference to service

    bool invalidFields;
    std::string txtRecordData = encodeTxtRecordData(service.txtRecords, invalidFields);
    if (invalidFields)
    {
        throw DnsSdError("Invalid fields in TXT record of service '"+service.name+"'");
    }

    DNSServiceErrorType errorCode =
        DNSServiceRegister(&sdRef,
                           (DNSServiceFlags)0,
                           toDnsSdInterfaceIndex(service.interfaceIndex),
                           service.name.c_str(),
                           toDnsSdStr(service.type),
                           toDnsSdStr(service.domain),
                           toDnsSdStr(service.host),
                           service.port,
                           txtRecordData.empty() ? 0 : txtRecordData.length()+1,
                           txtRecordData.empty() ? NULL : txtRecordData.c_str(),
                           &MDNSManager::PImpl::registerCallback, // callback pointer, called upon return from API
                           pimpl_.get());

    if (errorCode != kDNSServiceErr_NoError)
        throw DnsSdError(getDnsSdErrorName(errorCode));

    pimpl_->addServiceRef(sdRef);
}

void MDNSManager::registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                         const std::string &type,
                                         const std::string &domain,
                                         const MDNSServiceBrowser::Ptr & browser)
{
#if 0
    if (type.empty())
        throw std::logic_error("type argument can't be empty");

    AvahiPollGuard g(pimpl_->threadedPoll);

    MDNSManager::PImpl::AvahiBrowserRecord *browserRec = 0;
    auto it = pimpl_->browserRecords.find(browser);
    if (it == pimpl_->browserRecords.end())
    {
        it = pimpl_->browserRecords.insert(
                std::make_pair(browser,
                    MDNSManager::PImpl::AvahiBrowserRecord(browser, *pimpl_))).first;
    }
    browserRec = &it->second;

    AvahiServiceBrowser *sb = avahi_service_browser_new(pimpl_->client,
                                                        toAvahiIfIndex(interfaceIndex),
                                                        AVAHI_PROTO_UNSPEC,
                                                        toAvahiStr(type),
                                                        toAvahiStr(domain),
                                                        (AvahiLookupFlags)0,
                                                        MDNSManager::PImpl::AvahiBrowserRecord::browseCB,
                                                        browserRec);

    if (!sb)
    {
        // remove empty records
        if (browserRec->serviceBrowsers.empty())
            pimpl_->browserRecords.erase(it);
        throw AvahiClientError("avahi_service_browser_new() failed", pimpl_->client);
    }
    browserRec->serviceBrowsers.push_back(sb);
#endif
}

void MDNSManager::unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser)
{
#if 0
    AvahiPollGuard g(pimpl_->threadedPoll);

    pimpl_->browserRecords.erase(browser);
#endif
}

std::vector<std::string> MDNSManager::getErrorLog()
{
    std::vector<std::string> result;
    {
        std::lock_guard<std::mutex> g(pimpl_->mutex);
        result.swap(pimpl_->errorLog);
    }
    return result;
}

} // namespace MDNS
