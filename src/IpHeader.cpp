#include <iostream>
#include <sstream>
#include "IpHeader.h"
#include "Header.h"

IpHeader::IpHeader(const IpHeaderStruct* headerStruct):
    Header{reinterpret_cast<const unsigned char*>(headerStruct), sizeof(IpHeaderStruct)}
{
}

void IpHeader::print(std::stringstream& sstr) const
{
    IpHeader::print(sstr);
    sstr << IpHeader::toString() << std::endl;
}

std::string IpHeader::toString() const
{
    return "IpHeader";
}
