#ifndef MAC_ADDR_H
#define MAC_ADDR_H

#include <array>

#define MAC_ADDR_SIZE 6

class MacAddr
{
    std::array<uint8_t, MAC_ADDR_SIZE> m_addr;
public:
    MacAddr(uint8_t[MAC_ADDR_SIZE]);
    MacAddr(const std::array<uint8_t, MAC_ADDR_SIZE>&);
    std::array<uint8_t, MAC_ADDR_SIZE>::iterator begin();
    std::array<uint8_t, MAC_ADDR_SIZE>::const_iterator cbegin() const;
    std::array<uint8_t, MAC_ADDR_SIZE>::iterator end();
    std::array<uint8_t, MAC_ADDR_SIZE>::const_iterator cend() const;
};

#endif
