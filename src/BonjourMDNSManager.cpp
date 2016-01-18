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
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <algorithm>
#include <utility>

#include <iostream>

namespace MDNS
{

namespace
{

inline bool strEndsWith(const std::string &str, const std::string &strEnd)
{
    if (strEnd.size() > str.size())
        return false;
    if (strEnd.size() == str.size())
        return strEnd == str;
    std::string::const_reverse_iterator i = str.rbegin();
    std::string::const_reverse_iterator i1 = strEnd.rbegin();
    while (i1 != strEnd.rend())
    {
        if (*i != *i1)
            return false;
        ++i;
        ++i1;
    }
    return true;
}

inline void removeTrailingDot(std::string &str)
{
    if (str.length() > 0 && str[str.length()-1] == '.')
    {
        str.resize(str.length()-1);
    }
}

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

std::vector<std::string> decodeTxtRecordData(uint16_t txtLen, const unsigned char *txtRecord)
{
    std::vector<std::string> res;
    const unsigned char *cur = txtRecord;
    uint16_t i = 0;
    while (i < txtLen)
    {
        std::string::size_type len = static_cast<std::string::size_type>(*cur);
        if (len == 0)
            break;
        res.emplace_back(reinterpret_cast<const char*>(cur+1), len);
        cur += 1 + len;
        i += 1 + len;
    }
    return res;
}

std::string decodeDNSName(const std::string &str)
{
    std::string res;
    res.reserve(str.size()+2);
    for (std::string::const_iterator it = str.begin(), iend = str.end(); it != iend; ++it)
    {
        const char c = (*it);
        if (c == '\\')
        {
            if (++it == iend)
                break;
            const char c1 = *it;
            if (isdigit(c1))
            {
                if (++it == iend)
                    break;
                const char c2 = *it;
                if (isdigit(c2))
                {
                    if (++it == iend)
                        break;
                    const char c3 = *it;
                    if (isdigit(c3))
                    {
                        const char num[4] = {c1, c2, c3, '\0'};
                        res += static_cast<char>(atoi(num));
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                res += c1;
            }
        }
        else
        {
            res += c;
        }
    }
    return res;
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

class DNSServiceRefWrapper
{
public:

    DNSServiceRef serviceRef;

    DNSServiceRefWrapper(DNSServiceRef serviceRef)
        : serviceRef(serviceRef)
    { }

    DNSServiceRefWrapper(const DNSServiceRefWrapper &other) = delete;

    DNSServiceRefWrapper(DNSServiceRefWrapper &&other)
        : serviceRef(other.release())
    {
    }

    DNSServiceRef release()
    {
        DNSServiceRef tmp = serviceRef;
        serviceRef = (DNSServiceRef)0;
        return tmp;
    }

    ~DNSServiceRefWrapper()
    {
        if (serviceRef)
            DNSServiceRefDeallocate(serviceRef);
    }
};


} // unnamed namespace

class MDNSManager::PImpl
{
public:

    std::thread thread;
    std::mutex mutex;
    std::atomic<bool> processEvents;
    std::vector<DNSServiceRef> serviceRefs;

    struct BrowserRecord
    {
        MDNSServiceBrowser::Ptr handler;
        DNSServiceRef serviceRef;
        MDNSManager::PImpl &pimpl;

        BrowserRecord(const MDNSServiceBrowser::Ptr &handler, MDNSManager::PImpl &pimpl)
            : handler(handler), serviceRef(0), pimpl(pimpl)
        { }

        struct ResolveRecord
        {
            std::string type;
            std::string domain;
            BrowserRecord *parent;

            ResolveRecord(BrowserRecord *parent, std::string &&type, std::string &&domain)
                : type(std::move(type)), domain(std::move(domain)), parent(parent)
            {
            }
        };

        /**
         * browse callback
         */
        static void DNSSD_API browseCB(
                DNSServiceRef sdRef,
                DNSServiceFlags flags,
                uint32_t interfaceIndex,
                DNSServiceErrorType errorCode,
                const char *serviceName,
                const char *regtype,
                const char *replyDomain,
                void *context )
        {
            BrowserRecord *self = static_cast<BrowserRecord*>(context);
            if (flags & kDNSServiceFlagsAdd)
            {
                DNSServiceRef resolveRef;
                ResolveRecord *rr = new ResolveRecord(self, toDnsSdStr(regtype), toDnsSdStr(replyDomain));
                DNSServiceErrorType errorCode =
                    DNSServiceResolve(&resolveRef,
                                       (DNSServiceFlags)0,
                                       interfaceIndex,
                                       serviceName,
                                       regtype,
                                       replyDomain,
                                       &resolveCB,
                                       rr);

                if (errorCode == kDNSServiceErr_NoError)
                {
                    self->pimpl.addServiceRef(resolveRef);
                }
                else
                {
                    delete rr;
                    self->pimpl.error(std::string("DNSServiceResolve: ")+getDnsSdErrorName(errorCode));
                }
            }
            else
            {
                if (self->handler)
                    self->handler->onRemovedService(serviceName, regtype, replyDomain);
            }
        }

        static void DNSSD_API resolveCB(DNSServiceRef sdRef,
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
            ResolveRecord *rr = static_cast<ResolveRecord*>(context);
            BrowserRecord *self = static_cast<BrowserRecord*>(rr->parent);

            MDNSService service;
            service.interfaceIndex = fromDnsSdInterfaceIndex(interfaceIndex);

            std::string name = decodeDNSName(fromDnsSdStr(fullname));
            std::string suffix = std::string(".") + rr->type + rr->domain;
            std::string host = fromDnsSdStr(hosttarget);

            if (strEndsWith(name, suffix))
            {
                name.resize(name.length()-suffix.length());
            }

            // remove trailing '.'
            removeTrailingDot(rr->type);
            removeTrailingDot(rr->domain);
            removeTrailingDot(host);

            service.name = std::move(name);
            service.type = std::move(rr->type);
            service.domain = std::move(rr->domain);
            service.host = std::move(host);
            service.port = port;
            service.txtRecords = decodeTxtRecordData(txtLen, txtRecord);

            delete rr;

            if (self->handler)
                self->handler->onNewService(service);

            self->pimpl.removeServiceRef(sdRef);
        }

    };

    typedef std::unordered_multimap<MDNSServiceBrowser::Ptr, std::unique_ptr<BrowserRecord> > BrowserRecordMap;
    BrowserRecordMap browserRecordMap;

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
        for (auto it = serviceRefs.begin(), eit = serviceRefs.end(); it != eit; ++it)
        {
            DNSServiceRefDeallocate(*it);
        }
    }

    void eventLoop()
    {
        std::vector<DNSServiceRef> localRefs;
        fd_set readfds;
        struct timeval tv;

        while (processEvents)
        {

            {
                std::lock_guard<std::mutex> g(mutex);
                localRefs = serviceRefs;
            }

            int maxFD = 0;

            // 1. Set up the fd_set as usual here.
            FD_ZERO(&readfds);

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
            tv.tv_sec = 1; // wakes up every 1 sec if no socket activity occurs
            tv.tv_usec = 0;

            // wait for pending data or 5 secs to elapse:
            int result = select(nfds, &readfds, (fd_set*) 0, (fd_set*) 0, &tv);
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
                            error(std::string("DNSServiceProcessResult returned ")+getDnsSdErrorName(err));
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
                error(std::string("select() returned ")+std::to_string(result)+" errno "+
                      std::to_string(errno)+" "+strerror(errno));
            }

            std::this_thread::yield();
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
        std::lock_guard<std::mutex> g(mutex);

        if (errorHandler)
            errorHandler(errorMsg);
        errorLog.push_back(std::move(errorMsg));
    }

    /**
     * register callback
     */
    static void DNSSD_API registerCB(
        DNSServiceRef                       sdRef,
        DNSServiceFlags                     flags,
        DNSServiceErrorType                 errorCode,
        const char                          *name,
        const char                          *regtype,
        const char                          *domain,
        void                                *context )
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

    void removeServiceRef(DNSServiceRef serviceRef)
    {
        std::lock_guard<std::mutex> g(mutex);
        serviceRefs.erase( std::remove( serviceRefs.begin(), serviceRefs.end(), serviceRef ), serviceRefs.end() );
        DNSServiceRefDeallocate(serviceRef);
    }

    void addBrowserRecord(std::unique_ptr<BrowserRecord> brec)
    {
        std::lock_guard<std::mutex> g(mutex);
        serviceRefs.push_back(brec->serviceRef);
        browserRecordMap.insert(std::make_pair(brec->handler, std::move(brec)));
    }

    void removeBrowser(const MDNSServiceBrowser::Ptr & browser)
    {
        std::lock_guard<std::mutex> g(mutex);
        auto range = browserRecordMap.equal_range(browser);
        for (auto it = range.first, eit = range.second; it != eit; ++it)
        {
            serviceRefs.erase( std::remove( serviceRefs.begin(), serviceRefs.end(), it->second->serviceRef ), serviceRefs.end() );
            DNSServiceRefDeallocate(it->second->serviceRef);
        }
        browserRecordMap.erase(browser);
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
                           &MDNSManager::PImpl::registerCB, // callback pointer, called upon return from API
                           pimpl_.get());

    if (errorCode != kDNSServiceErr_NoError)
        throw DnsSdError(std::string("DNSServiceRegister: ")+getDnsSdErrorName(errorCode));

    pimpl_->addServiceRef(sdRef);
}

void MDNSManager::registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                         const std::string &type,
                                         const std::string &domain,
                                         const MDNSServiceBrowser::Ptr & browser)
{
    if (type.empty())
        throw std::logic_error("type argument can't be empty");

    std::unique_ptr<MDNSManager::PImpl::BrowserRecord> brec(new MDNSManager::PImpl::BrowserRecord(browser, *pimpl_));

    DNSServiceErrorType errorCode =
        DNSServiceBrowse(&brec->serviceRef,
                         (DNSServiceFlags)0,
                         toDnsSdInterfaceIndex(interfaceIndex),
                         toDnsSdStr(type),
                         toDnsSdStr(domain),
                         &MDNSManager::PImpl::BrowserRecord::browseCB,
                         brec.get());

    if (errorCode != kDNSServiceErr_NoError)
        throw DnsSdError(std::string("DNSServiceBrowse: ")+getDnsSdErrorName(errorCode));

    pimpl_->addBrowserRecord(std::move(brec));
}

void MDNSManager::unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser)
{
    pimpl_->removeBrowser(browser);
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
