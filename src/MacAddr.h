#ifndef MAC_ADDR_H
#define MAC_ADDR_H

#include <array>

#define MAC_ADDR_SIZE 6

class MacAddr
{
    std::array<uint8_t, MAC_ADDR_SIZE> m_addr;
public:
    MacAddr(uint8_t[MAC_ADDR_SIZE]);
    MacAddr(std::array<uint8_t, MAC_ADDR_SIZE>);
};


#endif
