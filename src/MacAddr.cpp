#include "MacAddr.h"

MacAddr::MacAddr(uint8_t arr[MAC_ADDR_SIZE])
{
    std::copy(arr, arr + MAC_ADDR_SIZE, std::begin(m_addr));
}

MacAddr::MacAddr(std::array<uint8_t, MAC_ADDR_SIZE> arr)
{
    std::copy(std::begin(arr), std::end(arr), std::begin(m_addr));
}

std::array<uint8_t, IP4_ADDR_SIZE>::iterator MacAddr::begin()
{
    return m_addr.begin();
}

std::array<uint8_t, IP4_ADDR_SIZE>::const_iterator MacAddr::cbegin()
{
    return m_addr.cbegin();
}

std::array<uint8_t, IP4_ADDR_SIZE>::iterator MacAddr::end()
{
    return m_addr.end();
}

std::array<uint8_t, IP4_ADDR_SIZE>::const_iterator MacAddr::cend()
{
    return m_addr.cend();
}
