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
    mgr.run();

    std::cout << "Running loop...";
    std::cin.get();
}
