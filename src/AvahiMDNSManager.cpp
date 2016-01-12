/*
 * AvahiMDNSManager.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */
#include "MDNSManager.hpp"
#include <avahi-common/error.h>
#include <avahi-common/thread-watch.h>
#include <avahi-client/client.h>
#include <string>
#include <stdexcept>
#include <sstream>

namespace MDNS
{

class AvahiError: public std::runtime_error
{
public:

    AvahiError(const std::string &message)
        : std::runtime_error(message)
    {
    }

    virtual ~AvahiError() noexcept
    {
    }
};

class AvahiClientError: public AvahiError
{
public:
    AvahiClientError(const std::string & reason, AvahiClient * client)
        : AvahiError(formatError(reason, avahi_client_errno(client))), error_(avahi_client_errno(client))
    {
    }

    AvahiClientError(const std::string & reason, int error)
        : AvahiError(formatError(reason, error)), error_(error)
    {
    }

    virtual ~AvahiClientError() noexcept
    {
    }

    int error()
    {
        return error_;
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

extern "C"
{
}

class MDNSManager::PImpl
{
public:
    AvahiClient *client_;
    AvahiThreadedPoll *threadedPoll_;

    PImpl()
        : client_(0), threadedPoll_(0)
    {
        if (!(threadedPoll_ = avahi_threaded_poll_new()))
        {
            throw AvahiError("Could not allocate Avahi threaded poll");
        }

        int error;

        if (!(client_ = avahi_client_new(avahi_threaded_poll_get(threadedPoll_), (AvahiClientFlags) 0, clientCB, this,
            &error)))
        {
            avahi_threaded_poll_free(threadedPoll_);
            throw AvahiClientError("Could not allocate Avahi client", error);
        }

    }

    ~PImpl()
    {
        stop();
        avahi_client_free(client_);
        avahi_threaded_poll_free(threadedPoll_);
    }

    void run()
    {
        if (avahi_threaded_poll_start(threadedPoll_) < 0)
        {
            throw AvahiError("Could not start Avahi threaded poll");
        }
    }

    void stop()
    {
        avahi_threaded_poll_stop(threadedPoll_);
    }

    static void clientCB(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata)
    {
        PImpl *pimpl = (PImpl*)userdata;
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

} // namespace MDNS
