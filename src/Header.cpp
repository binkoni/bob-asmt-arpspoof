#include <iostream>
#include <cstring>
#include "Header.h"
#include "UnknownHeader.h"
#include "EthHeader.h"
#include "ArpHeader.h"
#include "IpHeader.h"
#include "TcpHeader.h"

Header::Header() {}

Header::Header(const unsigned char* rawHeader, uint32_t rawHeaderLen)
{
    m_rawHeaderLen = rawHeaderLen;
    m_rawHeader = static_cast<unsigned char*>(malloc(m_rawHeaderLen));
    std::memcpy(m_rawHeader, rawHeader, rawHeaderLen);
}


Header::Header(uint32_t rawHeaderLen)
{
    m_rawHeaderLen = rawHeaderLen;
    m_rawHeader = static_cast<unsigned char*>(calloc(m_rawHeaderLen, sizeof(unsigned char)));
}

Header::~Header()
{
    delete m_rawHeader;
}

void* Header::headerStruct() const
{
    return m_rawHeader;
}


Header* Header::parse(const unsigned char* rawHeader, uint32_t rawHeaderLen)
{
    auto header = reinterpret_cast<const EthHeaderStruct*>(rawHeader);
    switch(MY_NTOHS(header->type))
    {
        case 0x0800:
            //return new UnknownHeader{rawHeader, rawHeaderLen};
            return parseIp(rawHeader, rawHeaderLen);
        case 0x0806:
            return new ArpHeader{reinterpret_cast<const ArpHeaderStruct*>(rawHeader)};
        default:
            return new UnknownHeader{};
    }
    return nullptr;
}

Header* Header::parseIp(const unsigned char* rawHeader, uint32_t rawHeaderLen)
{
    auto header = reinterpret_cast<const IpHeaderStruct*>(IP_HDR(rawHeader));
    if(header->proto == 0x06)
    {
        return new TcpHeader{reinterpret_cast<const TcpHeaderStruct*>(rawHeader)};
    }
    return new UnknownHeader{};
}

std::ostream& operator<<(std::ostream& ostr, const Header& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
