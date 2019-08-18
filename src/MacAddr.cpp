#include "MacAddr.h"

MacAddr::MacAddr(uint8_t arr[MAC_ADDR_SIZE])
{
    std::copy(arr, arr + MAC_ADDR_SIZE, std::begin(m_addr));
}

MacAddr::MacAddr(std::array<uint8_t, MAC_ADDR_SIZE> arr)
{
    std::copy(std::begin(arr), std::end(arr), std::begin(m_addr));
}
