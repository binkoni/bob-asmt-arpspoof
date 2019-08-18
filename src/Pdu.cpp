#include <iostream>
#include <cstring>
#include "Pdu.h"
#include "RawPdu.h"
#include "EthPdu.h"
#include "ArpPdu.h"
#include "Ip4Pdu.h"
#include "TcpPdu.h"

Pdu::Pdu() {}

Pdu::Pdu(const uint8_t* rawPdu, uint32_t rawPduSize)
{
    m_rawPduSize = rawPduSize;
    m_rawPdu = static_cast<uint8_t*>(malloc(m_rawPduSize));
    std::memcpy(m_rawPdu, rawPdu, rawPduSize);
}

Pdu::Pdu(uint32_t rawPduSize)
{
    m_rawPduSize = rawPduSize;
    m_rawPdu = static_cast<uint8_t*>(calloc(m_rawPduSize, sizeof(unsigned char)));
}

Pdu::~Pdu()
{
    delete m_rawPdu;
}

void* Pdu::header() const
{
    return m_rawPdu;
}

size_t Pdu::headerSize() const
{
    return m_rawPduSize;
}

Pdu* Pdu::parse(const uint8_t* rawPdu, uint32_t rawPduSize)
{
    auto ethHeader = reinterpret_cast<const EthHeader*>(rawPdu);
    switch(MY_NTOHS(ethHeader->ethtype))
    {
        case 0x0800:
            return parseIp(rawPdu, rawPduSize);
        case 0x0806:
            return new ArpPdu{reinterpret_cast<const ArpHeader*>(rawPdu + sizeof(EthHeader))};
        default:
            return new RawPdu{};
    }
    return nullptr;
}

Pdu* Pdu::parseIp(const uint8_t* rawPdu, uint32_t rawPduSize)
{
    auto ip4Header = reinterpret_cast<const Ip4Header*>(IP_HDR(rawPdu));
    if(ip4Header->proto == 0x06)
    {
        return new TcpPdu{reinterpret_cast<const TcpHeader*>(rawPdu + sizeof(EthHeader) + ip4Header->hlen * 4)};
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
