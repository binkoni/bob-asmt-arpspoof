#include <arpa/inet.h>
#include <array>
#include <boost/format.hpp>
#include <iostream>
#include <sstream>
#include "EthPdu.h"
#include "MacAddr.h"
#include "Pdu.h"

EthPdu::EthPdu(const EthHeader& header)
{
    Pdu::parse(&header, sizeof(EthHeader);
}

EthPdu::EthPdu(const EthHeader* header):
{
    Pdu::parse(reinterpret_cast<const uint8_t*>(header), sizeof(EthHeader));
}

EthPdu::EthPdu(const uint8_t* header):
{
    Pdu::parse(header, sizeof(EthHeader));
}

EthPdu::EthPdu():
{
    Pdu::parse(sizeof(EthHeader));
}

MacAddr EthPdu::dmac()
{
    auto header = static_cast<EthHeader* const>(EthPdu::data());
    return MacAddr{header->dmac};
}

MacAddr EthPdu::smac()
{
    auto header = static_cast<EthHeader* const>(EthPdu::data());
    return MacAddr{header->smac};
}

uint16_t EthPdu::ethtype()
{
    auto header = static_cast<EthHeader* const>(EthPdu::data());
    return ntohs(header->ethtype);
}

void EthPdu::dmac(const MacAddr& dmac)
{
    auto header = static_cast<EthHeader* const>(EthPdu::data());
    std::copy(dmac.cbegin(), dmac.cend(), header->dmac);
}

void EthPdu::smac(const MacAddr& smac)
{
    auto header = static_cast<EthHeader* const>(EthPdu::data());
    std::copy(smac.cbegin(), smac.cend(), header->smac);
}

void EthPdu::ethtype(uint16_t ethtype)
{
    auto header = static_cast<EthHeader* const>(EthPdu::data());
    header->ethtype = htons(ethtype);
}

/*
void EthPdu::print(std::stringstream& sstr) const
{
    sstr << EthPdu::toString() << std::endl;
}
*/

std::string EthPdu::toString() const
{
    std::stringstream sstr;
    auto hdr = static_cast<EthHeader*>(EthPdu::data());
    sstr << boost::format("eth dmac %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->dmac[0]) % int(hdr->dmac[1]) % int(hdr->dmac[2]) % int(hdr->dmac[3]) % int(hdr->dmac[4]) % int(hdr->dmac[5]);
    sstr << boost::format("eth smac %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->smac[0]) % int(hdr->smac[1]) % int(hdr->smac[2]) % int(hdr->smac[3]) % int(hdr->smac[4]) % int(hdr->smac[5]);
    sstr << boost::format("eth type 0x%04X\n") % int(MY_NTOHS(hdr->ethtype));
    return sstr.str();
}
