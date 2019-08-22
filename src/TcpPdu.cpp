#include <iostream>
#include <sstream>
#include "TcpPdu.h"
#include "Pdu.h"

TcpPdu::TcpPdu():
    Pdu{sizeof(TcpHeader)}
{}

TcpPdu::TcpPdu(const TcpHeader& header):
    Pdu{reinterpret_cast<const uint8_t*>(&header), sizeof(TcpHeader)}
{}

TcpPdu::TcpPdu(const TcpHeader* header):
    Pdu{reinterpret_cast<const uint8_t*>(header), sizeof(TcpHeader)}
{}

TcpPdu::TcpPdu(const uint8_t* header):
    Pdu{header, sizeof(TcpHeader)}
{}

/*
void TcpPdu::print(std::stringstream& sstr) const
{
    sstr << TcpPdu::toString() << std::endl;
}
*/
std::string TcpPdu::toString() const
{
    return "TcpPdu";
}
