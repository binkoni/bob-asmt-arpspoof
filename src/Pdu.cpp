#include <iostream>
#include <cstring>
#include "Pdu.h"
#include "RawPdu.h"
#include "EthPdu.h"
#include "ArpPdu.h"
#include "Ip4Pdu.h"
#include "TcpPdu.h"

Pdu::Pdu() {}

Pdu::Pdu(const uint8_t* data, uint32_t size)
{
    m_size = size;
    m_data = static_cast<uint8_t*>(malloc(m_size));
    std::memcpy(m_data, data, size);
}

Pdu::Pdu(uint32_t size)
{
    m_size = size;
    m_data = static_cast<uint8_t*>(calloc(m_size, sizeof(unsigned char)));
}

Pdu::~Pdu()
{
    delete m_data;
}

void* Pdu::data() const
{
    return m_data;
}

size_t Pdu::size() const
{
    return m_size;
}

Pdu* Pdu::parse(const uint8_t* data, uint32_t size)
{
    auto ethHeader = reinterpret_cast<const EthHeader*>(data);
    switch(MY_NTOHS(ethHeader->ethtype))
    {
        case 0x0800:
            return parseIp(data, size);
        case 0x0806:
            return new ArpPdu{reinterpret_cast<const ArpHeader*>(data + sizeof(EthHeader))};
        default:
            return new RawPdu{};
    }
    return nullptr;
}

Pdu* Pdu::parseIp(const uint8_t* data, uint32_t size)
{
    auto ip4Header = reinterpret_cast<const Ip4Header*>(IP_HDR(data));
    if(ip4Header->proto == 0x06)
    {
        return new TcpPdu{reinterpret_cast<const TcpHeader*>(data + sizeof(EthHeader) + ip4Header->hlen * 4)};
    }
    return new RawPdu{};
}
/*
std::ostream& operator<<(std::ostream& ostr, const Pdu& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
*/
