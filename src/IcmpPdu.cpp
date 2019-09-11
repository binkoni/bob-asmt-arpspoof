#include <arpa/inet.h>
#include <boost/format.hpp>
#include "IcmpPdu.h"
#include "Pdu.h"

IcmpPdu::IcmpPdu():
    Pdu{sizeof(IcmpHeader)}
{}

IcmpPdu::IcmpPdu(const IcmpHeader& header):
    Pdu{reinterpret_cast<const uint8_t*>(&header), sizeof(IcmpHeader)}
{}

IcmpPdu::IcmpPdu(const IcmpHeader* header):
    Pdu{reinterpret_cast<const uint8_t*>(header), sizeof(IcmpHeader)}
{}

IcmpPdu::IcmpPdu(const uint8_t* header):
    Pdu{header, sizeof(IcmpHeader)}
{}

uint8_t IcmpPdu::type() const
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    return header->type;
}

uint8_t IcmpPdu::code() const
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    return header->ver;
}

uint16_t IcmpPdu::chksum() const
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    return header->tos;
}

uint32_t IcmpPdu::misc() const
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    return ntohs(header->tlen);
}

void IcmpPdu::type(uint8_t type)
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    header->type = type;
}

void IcmpPdu::code(uint8_t code)
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    header->code = code;
}

void IcmpPdu::chksum(uint16_t chksum)
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    header->chksum = chksum;
}

void IcmpPdu::misc(uint16_t misc)
{
    auto header = static_cast<IcmpHeader* const>(IcmpPdu::data());
    header->misc = htons(misc);
}

std::string IcmpPdu::toString() const
{
    std::stringstream sstr;
    sstr << boost::format("icmp hlen %u\n") % int(IcmpPdu::hlen());
    sstr << boost::format("ipv4 ver %u\n") % int(IcmpPdu::ver());
    sstr << boost::format("ipv4 tos %u\n") % int(IcmpPdu::tos());
    sstr << boost::format("ipv4 tlen %u\n") % IcmpPdu::tlen();
    sstr << boost::format("ipv4 id %u\n") % IcmpPdu::id();
    sstr << boost::format("ipv4 flags %u\n") % IcmpPdu::flags();
    sstr << boost::format("ipv4 ttl %u\n") % int(IcmpPdu::ttl());
    sstr << boost::format("ipv4 proto %X\n") % int(IcmpPdu::proto());
    sstr << boost::format("ipv4 chksum %X\n") % IcmpPdu::chksum();
    sstr << boost::format("ipv4 sip %s\n") % IcmpPdu::sip().toString();
    sstr << boost::format("ipv4 dip %s\n") % IcmpPdu::dip().toString();

    return sstr.str();
}
