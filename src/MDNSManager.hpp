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

namespace MDNS
{

class MDNSManager
{
public:

    MDNSManager();

    ~MDNSManager();

    void run();

    void stop();

    static bool isAvailable();

private:
    class PImpl;
    std::unique_ptr<PImpl> pimpl_;
};

} // namespace MDNS

#endif /* MDNSMANAGER_HPP_INCLUDED */
