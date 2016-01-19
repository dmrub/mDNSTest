/*
 * testclient.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"
#include <iostream>

using namespace MDNS;

class MyBrowser: public MDNSServiceBrowser
{
public:

    MyBrowser(const std::string &name)
        : name_(name)
    { }

    void onNewService(const MDNSService &service) override
    {
        std::cerr << "New "<<name_<<" service "<<service.getName()<<" of type "<<service.getType()<<" on domain "<<service.getDomain()
                  <<" (interface: "<<service.getInterfaceIndex()<<", host: "<<service.getHost()
                  <<", port "<<service.getPort()<<")"<<std::endl;
        if (!service.getTxtRecords().empty())
        {
            std::cerr << "  TXT ["<<std::endl;
            for (auto it = service.getTxtRecords().begin(), iend = service.getTxtRecords().end(); it != iend; ++it)
            {
                std::cerr<<"    "<<*it<<std::endl;
            }
            std::cerr << "  ]"<<std::endl;
        }
    }

    void onRemovedService(const std::string &name, const std::string &type, const std::string &domain) override
    {
        std::cerr<<"Removed "<<name_<<" service "<<name<<" of type "<<type<<" on domain "<<domain<<std::endl;
    }

private:
    std::string name_;
};

int main(int argc, char **argv)
{
    MDNSManager mgr;

    MDNSService s;

    mgr.setAlternativeServiceNameHandler([](const std::string &newName, const std::string &oldName)
    {
        std::cerr<<"ALTERNATIVE SERVICE NAME "<<newName<<" FOR "<<oldName<<std::endl;
    });

    mgr.setErrorHandler([](const std::string &errorMsg)
    {
        std::cerr<<"ERROR "<<errorMsg<<std::endl;
    });

    MyBrowser::Ptr httpBrowser = std::make_shared<MyBrowser>("HTTP");
    MyBrowser::Ptr arvidaBrowser = std::make_shared<MyBrowser>("ARVIDA");

    mgr.registerServiceBrowser(MDNS_IF_ANY, "_http._tcp", "", httpBrowser);
    mgr.registerServiceBrowser(MDNS_IF_ANY, "_http._tcp", {"_arvida"}, "", arvidaBrowser);

    s.setName("MyService").setPort(8080).setType("_http._tcp").addTxtRecord("path=/foobar");
    mgr.registerService(s);

    std::cout << "Running loop...";
    mgr.run();

    s.setName("ARVIDA Service").setPort(9090).addSubtype("_arvida").addTxtRecord("FOO=BOO");
    mgr.registerService(s);

    std::cin.get();

    std::cout<<"Exiting"<<std::endl;
}
