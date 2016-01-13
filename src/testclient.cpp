/*
 * testclient.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"
#include <iostream>

using namespace MDNS;

int main(int argc, char **argv)
{
    MDNSManager mgr;

    MDNSService s;

    s.name = "MyService";
    s.port = 8080;
    s.type = "_http._tcp";
    s.txtRecords.push_back("path=/foobar");
    mgr.registerService(s);
    mgr.run();

    s.name = "ARVIDA Service";
    s.port = 9090;
    s.txtRecords.push_back("FOO=BOO");
    mgr.registerService(s);

    std::cout << "Running loop...";
    std::cin.get();
}
