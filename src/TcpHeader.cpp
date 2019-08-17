#include <iostream>
#include <sstream>
#include "TcpHeader.h"
#include "Header.h"

TcpHeader::TcpHeader(const TcpHeaderStruct* headerStruct):
    Header{reinterpret_cast<const unsigned char*>(headerStruct), sizeof(TcpHeaderStruct)}
{
}

TcpHeader::TcpHeader():
    Header{sizeof(TcpHeaderStruct)}
{
}

void TcpHeader::print(std::stringstream& sstr) const
{
    sstr << TcpHeader::toString() << std::endl;
}

std::string TcpHeader::toString() const
{
    return "TcpHeader";
}
