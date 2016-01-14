/*
 * AvahiMDNSManager.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */
#include "MDNSManager.hpp"
#include <avahi-common/error.h>
#include <avahi-common/thread-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/alternative.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <string>
#include <stdexcept>
#include <sstream>
#include <cassert>
#include <unordered_map>

namespace MDNS
{

namespace
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

inline AvahiIfIndex toAvahiIfIndex(MDNSInterfaceIndex i)
{
    if (i == MDNS_IF_ANY)
    {
        return AVAHI_IF_UNSPEC;
    }
    return static_cast<AvahiIfIndex>(i);
}

inline MDNSInterfaceIndex fromAvahiIfIndex(AvahiIfIndex i)
{
    if (i == AVAHI_IF_UNSPEC)
    {
        return MDNS_IF_ANY;
    }
    return static_cast<MDNSInterfaceIndex>(i);
}

AvahiStringList * toAvahiStringList(const std::vector<std::string> & data)
{
    AvahiStringList * list = 0;

    for (auto it = data.begin(), et = data.end(); it != et; ++it)
    {
        list = avahi_string_list_add(list, it->c_str());
    }

    return list;
}

std::vector<std::string> fromAvahiStrList(AvahiStringList * list)
{
    std::vector < std::string > res;

    for (AvahiStringList * i = list; i != 0; i = avahi_string_list_get_next(i))
    {
        res.emplace_back(
                reinterpret_cast<const char *>(avahi_string_list_get_text(i)),
                avahi_string_list_get_size(i));
    }

    return res;
}

inline const char * toAvahiStr(const std::string & str)
{
    return str.empty() ? 0 : str.c_str();
}

class AvahiPollGuard
{
public:

    AvahiPollGuard(AvahiThreadedPoll *threadedPoll)
        : threadedPoll_(threadedPoll)
    {
        avahi_threaded_poll_lock(threadedPoll_);
    }

    ~AvahiPollGuard()
    {
        avahi_threaded_poll_unlock(threadedPoll_);
    }

private:
    AvahiThreadedPoll *threadedPoll_;
};


} // unnamed namespace

class MDNSManager::PImpl
{
public:

    struct AvahiServiceRecord
    {
        std::string serviceName;
        AvahiEntryGroup *group;
        std::vector<MDNSService> services;
        size_t nextToRegister;
        MDNSManager::PImpl &pimpl;

        AvahiServiceRecord(const std::string &name, MDNSManager::PImpl &pimpl)
            : serviceName(name), group(0), services(), nextToRegister(0), pimpl(pimpl)
        {
        }

        ~AvahiServiceRecord()
        {
            if (group)
            {
                avahi_entry_group_reset(group);
                avahi_entry_group_free(group);
            }
        }

        void selectAlternativeServiceName()
        {
            char * altName = avahi_alternative_service_name(serviceName.c_str());
            if (altName)
            {
                serviceName = altName;
                avahi_free(altName);
            }
        }

        void resetServices()
        {
            if (group)
            {
                avahi_entry_group_reset(group);
                nextToRegister = 0;
            }
        }

        static void entryGroupCB(AvahiEntryGroup *g, AvahiEntryGroupState state,
                AVAHI_GCC_UNUSED void *userdata)
        {
            AvahiServiceRecord * self =
                reinterpret_cast<AvahiServiceRecord*>(userdata);
            assert(g == self->group || self->group == 0);

            if (self->group == 0)
            {
                self->group = g;
            }

            switch (state)
            {
                case AVAHI_ENTRY_GROUP_ESTABLISHED:
                    /* The entry group has been established successfully */
                    //fprintf(stderr, "Service '%s' successfully established.\n", name);
                    break;

                case AVAHI_ENTRY_GROUP_COLLISION:
                {
                    /* A service name collision with a remote service
                     * happened. Let's pick a new name */
                    self->selectAlternativeServiceName();
                    /* And recreate the services */
                    avahi_entry_group_reset(self->group);
                    self->nextToRegister = 0;
                    self->registerMissingServices(avahi_entry_group_get_client(g));
                    break;
                }

                case AVAHI_ENTRY_GROUP_FAILURE:
                    self->pimpl.avahiError("Entry group failure",
                                     avahi_entry_group_get_client(g));
                    avahi_threaded_poll_quit(self->pimpl.threadedPoll);
                    break;
                case AVAHI_ENTRY_GROUP_UNCOMMITED:
                case AVAHI_ENTRY_GROUP_REGISTERING:
                    break;
                default:
                    self->pimpl.error("Unexpected AvahiEntryGroupState value");
            }
        }

        bool registerMissingServices(AvahiClient *client)
        {
            assert(client);

            if (!group)
            {
                if (!(group = avahi_entry_group_new(client, &entryGroupCB,
                                                    reinterpret_cast<void*>(this))))
                {
                    pimpl.avahiError("avahi_entry_group_new() failed : ",
                                     client);
                    avahi_threaded_poll_quit(pimpl.threadedPoll);
                    return false;
                }
            }

            //resetting and resubmitting all
            if (services.size() > 0 && nextToRegister > 0)
            {
                avahi_entry_group_reset(group);
                nextToRegister = 0;
            }

            bool repeatRegistration;
            bool needToCommit;

            do
            {
                repeatRegistration = false;
                needToCommit = false;
                while (nextToRegister < services.size())
                {
                    int error = registerService(client, services[nextToRegister]);

                    if (error == AVAHI_OK)
                    {
                        needToCommit = true;
                    }
                    else if (error == AVAHI_ERR_COLLISION)
                    {
                        selectAlternativeServiceName();
                        avahi_entry_group_reset(group);
                        nextToRegister = 0;
                        repeatRegistration = true;
                        break;
                    }
                    else
                    {
                        return false;
                    }
                    ++nextToRegister;
                }
            } while (repeatRegistration);

            if (!needToCommit)
            {
                return true;
            }

            int ret = avahi_entry_group_commit(group);
            if (ret < 0)
            {
                pimpl.avahiError("Failed to commit entry group", ret);
                avahi_threaded_poll_quit(pimpl.threadedPoll);
                return false;
            }
            return true;
        }

        /**
         * Returns avahi error code
         */
        int registerService(AvahiClient *client, const MDNSService &service)
        {
            assert(client);
            assert(group);

            AvahiStringList *txtRecords = toAvahiStringList(service.txtRecords);

            int error = avahi_entry_group_add_service_strlst(
                    group, toAvahiIfIndex(service.interfaceIndex),
                    AVAHI_PROTO_UNSPEC, (AvahiPublishFlags) 0, serviceName.c_str(),
                    toAvahiStr(service.type), toAvahiStr(service.domain),
                    toAvahiStr(service.host), service.port, txtRecords);

            avahi_string_list_free(txtRecords);

            if (error == AVAHI_ERR_COLLISION)
            {
                return false;
            }

            if (error < 0)
            {
                pimpl.avahiError("avahi_entry_group_add_service_strlst() failed", error);
                avahi_threaded_poll_quit(pimpl.threadedPoll);
                return error;
            }

            for (auto it = service.subtypes.begin(), et = service.subtypes.end();
                    it != et; ++it)
            {
                error = avahi_entry_group_add_service_subtype(
                        group, toAvahiIfIndex(service.interfaceIndex),
                        AVAHI_PROTO_UNSPEC, (AvahiPublishFlags) 0,
                        serviceName.c_str(), toAvahiStr(service.type),
                        toAvahiStr(service.domain), it->c_str());
                if (error < 0)
                {
                    pimpl.avahiError("avahi_entry_group_add_service_subtype() failed", error);
                    avahi_threaded_poll_quit(pimpl.threadedPoll);
                    return error;
                }
            }
            return AVAHI_OK;
        }
    };

    typedef std::unordered_map<std::string, AvahiServiceRecord> AvahiServiceRecordMap;

    AvahiClient *client;
    bool clientRunning;
    AvahiThreadedPoll *threadedPoll;
    AvahiServiceRecordMap serviceRecords;
    std::vector<std::string> errorLog;

    PImpl()
        : client(0), clientRunning(false), threadedPoll(0), serviceRecords()
    {
        if (!(threadedPoll = avahi_threaded_poll_new()))
        {
            throw AvahiError("Could not allocate Avahi threaded poll");
        }

        int error;

        if (!(client = avahi_client_new(avahi_threaded_poll_get(threadedPoll),
                                        (AvahiClientFlags) 0, clientCB, this,
                                        &error)))
        {
            avahi_threaded_poll_free(threadedPoll);
            throw AvahiClientError("Could not allocate Avahi client", error);
        }
    }

    ~PImpl()
    {
        stop();
        avahi_client_free(client);

        for (auto it = serviceRecords.begin(), eit = serviceRecords.end();
                it != eit; ++it)
        {
            // group pointer is destroyed by avahi_client_free
            it->second.group = 0;
        }

        avahi_threaded_poll_free(threadedPoll);
    }

    void run()
    {
        if (avahi_threaded_poll_start(threadedPoll) < 0)
        {
            throw AvahiError("Could not start Avahi threaded poll");
        }
    }

    void stop()
    {
        avahi_threaded_poll_stop(threadedPoll);
    }

    void registerMissingServices(AvahiClient *client)
    {
        if (!clientRunning)
            return;
        for (auto it = serviceRecords.begin(), eit = serviceRecords.end();
                it != eit; ++it)
        {
            it->second.registerMissingServices(client);
        }
    }

    void resetServices()
    {
        for (auto it = serviceRecords.begin(), eit = serviceRecords.end();
                it != eit; ++it)
        {
            it->second.resetServices();
        }
    }

    void error(std::string errorMsg)
    {
        errorLog.push_back(std::move(errorMsg));
    }

    void avahiError(const std::string & what, int errorCode)
    {
        std::ostringstream os;
        os << what << " error " << errorCode << ": " << avahi_strerror(errorCode);
        error(os.str());
    }

    void avahiError(const std::string & what, AvahiClient *client)
    {
        avahiError(what, avahi_client_errno(client));
    }

    static void clientCB(AvahiClient *client, AvahiClientState state,
            AVAHI_GCC_UNUSED void * userdata)
    {
        PImpl *self = (PImpl*) userdata;

        assert(client);

        switch (state)
        {
            case AVAHI_CLIENT_S_RUNNING:
                self->clientRunning = true;
                /* The server has startup successfully and registered its host
                 * name on the network, so it's time to create our services */
                self->registerMissingServices(client);
                break;

            case AVAHI_CLIENT_FAILURE:
            {
                self->avahiError("Client failure", client);
                avahi_threaded_poll_quit(self->threadedPoll);
                break;
            }
            case AVAHI_CLIENT_S_COLLISION:
                /* Let's drop our registered services. When the server is back
                 * in AVAHI_SERVER_RUNNING state we will register them
                 * again with the new host name. */
            case AVAHI_CLIENT_S_REGISTERING:
                /* The server records are now being established. This
                 * might be caused by a host name change. We need to wait
                 * for our own records to register until the host name is
                 * properly established. */
                self->resetServices();
                break;

            case AVAHI_CLIENT_CONNECTING:
                break;
            default:
                self->error("Unexpected AvahiClient state");
        }
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

void MDNSManager::registerService(MDNSService service)
{
    AvahiPollGuard g(pimpl_->threadedPoll);

    MDNSManager::PImpl::AvahiServiceRecord *serviceRec = 0;
    auto it = pimpl_->serviceRecords.find(service.name);
    if (it != pimpl_->serviceRecords.end())
    {
        serviceRec = &it->second;
    }
    else
    {
        serviceRec = &pimpl_->serviceRecords.insert(
            std::make_pair(service.name,
                MDNSManager::PImpl::AvahiServiceRecord(service.name, *pimpl_))).first->second;
    }

    serviceRec->services.push_back(std::move(service));
    pimpl_->registerMissingServices(pimpl_->client);
}

std::vector<std::string> MDNSManager::getErrorLog()
{

    std::vector<std::string> result;
    {
        AvahiPollGuard g(pimpl_->threadedPoll);
        result.swap(pimpl_->errorLog);
    }
    return result;
}

} // namespace MDNS
