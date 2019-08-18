#include <iostream>
#include <sstream>
#include "TcpPdu.h"
#include "Pdu.h"

TcpPdu::TcpPdu(const TcpHeader& header):
    Pdu{reinterpret_cast<const unsigned char*>(&header), sizeof(TcpHeader)}
{
}

TcpPdu::TcpPdu():
    Header{sizeof(TcpHeader)}
{
}

/*
void TcpPdu::print(std::stringstream& sstr) const
{
    sstr << TcpPdu::toString() << std::endl;
}

std::string TcpPdu::toString() const
{
    return "TcpPdu";
}
*/
