#include <boost/format.hpp>
#include "MacAddr.h"

MacAddr::MacAddr(uint8_t arr[MAC_ADDR_SIZE])
{
    std::copy(arr, arr + MAC_ADDR_SIZE, std::begin(m_addr));
}

MacAddr::MacAddr(const std::array<uint8_t, MAC_ADDR_SIZE>& arr)
{
    std::copy(std::begin(arr), std::end(arr), std::begin(m_addr));
}

std::string MacAddr::toString()
{
    return boost::str(boost::format("%02x:%02x:%02x:%02x:%02x:%02x") % int(m_addr[0]) % int(m_addr[1]) % int(m_addr[2]) % int(m_addr[3]) % int(m_addr[4]) % int(m_addr[5]));
}

std::array<uint8_t, MAC_ADDR_SIZE>::iterator MacAddr::begin()
{
    return m_addr.begin();
}

std::array<uint8_t, MAC_ADDR_SIZE>::const_iterator MacAddr::cbegin() const
{
    return m_addr.cbegin();
}

std::array<uint8_t, MAC_ADDR_SIZE>::iterator MacAddr::end()
{
    return m_addr.end();
}

std::array<uint8_t, MAC_ADDR_SIZE>::const_iterator MacAddr::cend() const
{
    return m_addr.cend();
}
