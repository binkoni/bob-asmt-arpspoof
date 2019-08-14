#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include "EthHeader.h"
#include "Header.h"

EthHeader::EthHeader(const EthHeaderStruct* headerStruct):
    Header{}
{
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
    sstr << boost::format("eth type 0x%04X\n") % int(MY_NTOHS(hdr->type));

    return sstr.str();
}
