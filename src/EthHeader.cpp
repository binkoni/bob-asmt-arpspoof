#include <array>
#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include <arpa/inet.h>
#include "EthHeader.h"
#include "Header.h"

EthHeader::EthHeader(const EthHeaderStruct* headerStruct):
    Header{reinterpret_cast<const unsigned char*>(headerStruct), sizeof(EthHeaderStruct)}
{
}

EthHeader::EthHeader():
    Header{sizeof(EthHeaderStruct)}
{
}

std::array<uint8_t, 6> EthHeader::dmac()
{
    auto headerStruct = static_cast<EthHeaderStruct*>(EthHeader::headerStruct());
    std::array<uint8_t, 6> dmac;
    std::copy(headerStruct->dmac, headerStruct->dmac + 6, std::begin(dmac));
    return dmac;
}

std::array<uint8_t, 6> EthHeader::smac()
{
    auto headerStruct = static_cast<EthHeaderStruct*>(EthHeader::headerStruct());
    std::array<uint8_t, 6> smac;
    std::copy(headerStruct->smac, headerStruct->smac + 6, std::begin(smac));
    return smac;
}

uint16_t EthHeader::ethtype()
{
    auto headerStruct = static_cast<EthHeaderStruct*>(EthHeader::headerStruct());
    return ntohs(headerStruct->ethtype);
}

void EthHeader::dmac(std::array<uint8_t, 6> dmac)
{
    auto headerStruct = static_cast<EthHeaderStruct*>(EthHeader::headerStruct());
    std::copy(std::begin(dmac), std::end(dmac), headerStruct->dmac);
}

void EthHeader::smac(std::array<uint8_t, 6> smac)
{
    auto headerStruct = static_cast<EthHeaderStruct*>(EthHeader::headerStruct());
    std::copy(std::begin(smac), std::end(smac), headerStruct->smac);
}

void EthHeader::ethtype(uint16_t ethtype)
{
    auto headerStruct = static_cast<EthHeaderStruct*>(EthHeader::headerStruct());
    headerStruct->ethtype = htons(ethtype);
}

void EthHeader::print(std::stringstream& sstr) const
{
    sstr << EthHeader::toString() << std::endl;
}

std::string EthHeader::toString() const
{
    std::stringstream sstr;
    auto hdr = static_cast<EthHeaderStruct*>(headerStruct());
    sstr << boost::format("eth dmac %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->dmac[0]) % int(hdr->dmac[1]) % int(hdr->dmac[2]) % int(hdr->dmac[3]) % int(hdr->dmac[4]) % int(hdr->dmac[5]);
    sstr << boost::format("eth smac %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->smac[0]) % int(hdr->smac[1]) % int(hdr->smac[2]) % int(hdr->smac[3]) % int(hdr->smac[4]) % int(hdr->smac[5]);
    sstr << boost::format("eth type 0x%04X\n") % int(MY_NTOHS(hdr->ethtype));

    return sstr.str();
}
