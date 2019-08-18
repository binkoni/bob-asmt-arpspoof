#include <iostream>
#include <cstring>
#include "Pdu.h"
#include "UnknownPdu.h"
#include "EthPdu.h"
#include "ArpPdu.h"
#include "IpPdu.h"
#include "TcpPdu.h"

Pdu::Pdu() {}

Pdu::Pdu(const uint8_t* rawPdu, uint32_t rawPduLen)
{
    m_rawPduLen = rawPduLen;
    m_rawPdu = static_cast<uint8_t*>(malloc(m_rawPduLen));
    std::memcpy(m_rawPdu, rawPdu, rawPduLen);
}

Pdu::Pdu(uint32_t rawPduLen)
{
    m_rawPduLen = rawPduLen;
    m_rawPdu = static_cast<uint8_t*>(calloc(m_rawPduLen, sizeof(unsigned char)));
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
    return m_rawPduLen;
}


Pdu* Pdu::parse(const uint8_t* rawPdu, uint32_t rawPduLen)
{
    auto pdu = reinterpret_cast<const EthHeader*>(rawPdu);
    switch(MY_NTOHS(pdu->ethtype))
    {
        case 0x0800:
            //return new UnknownPdu{rawPdu, rawPduLen};
            return parseIp(rawPdu, rawPduLen);
        case 0x0806:
            return new ArpPdu{reinterpret_cast<const ArpHeader*>(rawPdu + sizeof(EthHeader))};
        default:
            return new UnknownPdu{};
    }
    return nullptr;
}

Pdu* Pdu::parseIp(const uint8_t* rawPdu, uint32_t rawPduLen)
{
    auto pdu = reinterpret_cast<const IpHeader*>(IP_HDR(rawPdu));
    if(pdu->proto == 0x06)
    {
        return new TcpPdu{reinterpret_cast<const TcpHeader*>(rawPdu + sizeof(EthHeader) + pdu->hlen * 4)};
    }
    return new UnknownPdu{};
}

std::ostream& operator<<(std::ostream& ostr, const Pdu& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
