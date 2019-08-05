#ifndef HELPER_H
#define HELPER_H

#include <string>

namespace Helper
{
    std::string toMacString(uint8_t mac[6]); 
    std::string toIpString(uint8_t ip[6]);
    std::string toIpString(uint32_t ipInt);
}

#endif
