#include <algorithm>
#include <arpa/inet.h>
#include "Ip4Addr.h"

Ip4Addr::Ip4Addr(const char* str)
{
    struct sockaddr_in sockAddr;
    inet_pton(AF_INET, str, &sockAddr.sin_addr);
    std::copy_n(
        reinterpret_cast<uint8_t*>(&sockAddr.sin_addr),
        IP4_ADDR_SIZE,
        std::begin(m_addr)
    );
}

Ip4Addr::Ip4Addr(const struct sockaddr& sockAddr)
{
    std::copy_n(
        reinterpret_cast<const uint8_t*>(reinterpret_cast<const struct sockaddr_in*>(&sockAddr)->sin_addr.s_addr),
        IP4_ADDR_SIZE,
        std::begin(m_addr)
    );
}

Ip4Addr::Ip4Addr(std::string string)
{
    struct sockaddr_in sockAddr;
    inet_pton(AF_INET, string.c_str(), &sockAddr.sin_addr);
    std::copy_n(
        reinterpret_cast<uint8_t*>(&sockAddr.sin_addr),
        IP4_ADDR_SIZE,
        std::begin(m_addr)
    );
}

Ip4Addr::Ip4Addr(uint32_t num)
{
    std::copy_n(
        reinterpret_cast<uint8_t*>(&num),
        IP4_ADDR_SIZE,
        std::begin(m_addr)
    );
}

Ip4Addr::Ip4Addr(uint8_t arr[IP4_ADDR_SIZE])
{
    std::copy_n(arr, IP4_ADDR_SIZE, std::begin(m_addr));
}

Ip4Addr::Ip4Addr(std::array<uint8_t, IP4_ADDR_SIZE> arr)
{
    m_addr = arr;
}

std::array<uint8_t, IP4_ADDR_SIZE>::iterator Ip4Addr::begin()
{
    return m_addr.begin();
}

std::array<uint8_t, IP4_ADDR_SIZE>::const_iterator Ip4Addr::cbegin() const
{
    return m_addr.cbegin();
}

std::array<uint8_t, IP4_ADDR_SIZE>::iterator Ip4Addr::end()
{
    return m_addr.end();
}

std::array<uint8_t, IP4_ADDR_SIZE>::const_iterator Ip4Addr::cend() const
{
    return m_addr.cend();
}
