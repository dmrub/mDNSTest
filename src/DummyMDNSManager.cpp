/*
 * DummyMDNSManager.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */
#include "MDNSManager.hpp"
#include <stdexcept>

namespace MDNS
{

MDNSManager::MDNSManager()
    : pimpl_(0)
{
    throw std::logic_error("No MDNS support available");
}

MDNSManager::~MDNSManager()
{
}

bool MDNSManager::isAvailable()
{
    return false;
}

void MDNSManager::run()
{
}

void MDNSManager::stop()
{
}

} // namespace MDNS
