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

class MDNSManager
{
public:

    MDNSManager();

    ~MDNSManager();

    void run();

    void stop();

    void registerService(MDNSService service);

    static bool isAvailable();

private:
    class PImpl;
    std::unique_ptr<PImpl> pimpl_;
};

} // namespace MDNS

#endif /* MDNSMANAGER_HPP_INCLUDED */
