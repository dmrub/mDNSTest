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
        std::cerr << "New "<<name_<<" service "<<service.name<<" of type "<<service.type<<" on domain "<<service.domain
                <<" (interface: "<<service.interfaceIndex<<", host: "<<service.host
                <<", port "<<service.port<<")"<<std::endl;
        if (!service.txtRecords.empty())
        {
            std::cerr << "  TXT ["<<std::endl;
            for (auto it = service.txtRecords.begin(), iend = service.txtRecords.end(); it != iend; ++it)
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

    s.name = "MyService";
    s.port = 8080;
    s.type = "_http._tcp";
    s.txtRecords.push_back("path=/foobar");
    mgr.registerService(s);

    std::cout << "Running loop...";
    mgr.run();

    s.name = "ARVIDA Service";
    s.port = 9090;
    s.subtypes.push_back("_arvida");
    s.txtRecords.push_back("FOO=BOO");
    mgr.registerService(s);

    std::cin.get();

    std::cout<<"Exiting"<<std::endl;
}
