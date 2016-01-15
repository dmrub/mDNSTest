/*
 * MDNSManager.hpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#ifndef MDNSMANAGER_HPP_INCLUDED
#define MDNSMANAGER_HPP_INCLUDED

#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <utility>
#include <mutex>
#include <cstdint>

namespace MDNS
{

typedef uint32_t MDNSInterfaceIndex;
const MDNSInterfaceIndex MDNS_IF_ANY = 0; // use any interface for the service

class MDNSService
{
public:

    MDNSInterfaceIndex interfaceIndex;
    std::string name;                    // name of the service
    std::string type;                    // the service type followed by the protocol
    std::string domain;                  // if not empty, specifies the domain on which to advertise the service
    std::string host;                    // if not empty, specifies the SRV target host name.
    unsigned int port;                   // the port, in network byte order, on which the service accepts connections.
    std::vector<std::string> txtRecords; // TXT records
    std::vector<std::string> subtypes;   // subtypes of the service

    MDNSService()
        : interfaceIndex(MDNS_IF_ANY)
        , name()
        , type()
        , domain()
        , host()
        , port()
        , txtRecords()
        , subtypes()
    {
    }

    MDNSService(const MDNSService &other)
        : interfaceIndex(other.interfaceIndex)
        , name(other.name)
        , type(other.type)
        , domain(other.domain)
        , host(other.host)
        , port(other.port)
        , txtRecords(other.txtRecords)
        , subtypes(other.subtypes)
    { }

    MDNSService(MDNSService &&other)
        : interfaceIndex(other.interfaceIndex)
        , name(std::move(other.name))
        , type(std::move(other.type))
        , domain(std::move(other.domain))
        , host(std::move(other.host))
        , port(other.port)
        , txtRecords(std::move(other.txtRecords))
        , subtypes(std::move(other.subtypes))
    { }

    MDNSService(const std::string &name)
        : interfaceIndex(MDNS_IF_ANY)
        , name(name)
        , type()
        , domain()
        , host()
        , port()
        , txtRecords()
        , subtypes()
    { }

    MDNSService & operator=(const MDNSService &other)
    {
        if (this != &other)
        {
            interfaceIndex = other.interfaceIndex;
            name = other.name;
            type = other.type;
            domain = other.domain;
            host = other.host;
            port = other.port;
            txtRecords = other.txtRecords;
            subtypes = other.subtypes;
        }
        return *this;
    }

    MDNSService & operator=(MDNSService &&other)
    {
        if (this != &other)
        {
            interfaceIndex = other.interfaceIndex;
            name = other.name;
            type = other.type;
            domain = other.domain;
            host = other.host;
            port = other.port;
            txtRecords = other.txtRecords;
            subtypes = other.subtypes;
        }
        return *this;
    }

};

class MDNSServiceBrowser
{
public:

    typedef std::shared_ptr<MDNSServiceBrowser> Ptr;

    virtual void onNewService(const MDNSService &service) { }

    virtual void onRemovedService(const std::string &name, const std::string &type, const std::string &domain) { }

    virtual ~MDNSServiceBrowser() { }
};

class MDNSManager
{
public:

    typedef std::function<void (const std::string &newName, const std::string &oldName)> AlternativeServiceNameHandler;

    typedef std::function<void (const std::string &errorMsg)> ErrorHandler;

    MDNSManager();

    ~MDNSManager();

    void run();

    void stop();

    /**
     * Register handler for service name changes due to conflicts. Handler is executed in the event loop thread.
     */
    void setAlternativeServiceNameHandler(AlternativeServiceNameHandler handler);

    /**
     * Register handler for errors. Handler is executed in the event loop thread.
     */
    void setErrorHandler(ErrorHandler handler);

    void registerService(MDNSService service);

    /**
     * Register service browser for services on specified interface index,
     * service type, and domain.
     * Browser handler methods are called in event loop thread.
     */
    void registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                const std::string &type,
                                const std::string &domain,
                                const MDNSServiceBrowser::Ptr & browser);

    /**
     * Unregister service
     */
    void unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser);

    /**
     * Returns all error messages collected from last call to getErrorLog().
     */
    std::vector<std::string> getErrorLog();

    static bool isAvailable();

private:
    class PImpl;
    std::unique_ptr<PImpl> pimpl_;
};

} // namespace MDNS

#endif /* MDNSMANAGER_HPP_INCLUDED */
