#ifndef UTILS_H
#define UTILS_H

#include <string>

namespace Utils
{
    std::string toMacString(uint8_t mac[6]); 
    std::string toIpString(uint8_t ip[6]);
    std::string toIpString(uint32_t ipInt);
}

#endif
