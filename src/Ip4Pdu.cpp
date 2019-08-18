#include <iostream>
#include <sstream>
#include "Ip4Pdu.h"
#include "Pdu.h"

Ip4Pdu::Ip4Pdu(const Ip4Header& header):
    Pdu{reinterpret_cast<const unsigned char*>(&header), sizeof(Ip4Header)}
{}

Ip4Pdu::Ip4Pdu(Ip4Header&& header):
    Pdu{reinterpret_cast<const unsigned char*>(&header), sizeof(Ip4Header)}
{}

Ip4Pdu::Ip4Pdu():
    Pdu{sizeof(Ip4Header)}
{}

/*
void Ip4Pdu::print(std::stringstream& sstr) const
{
    Ip4Pdu::print(sstr);
    sstr << Ip4Pdu::toString() << std::endl;
}

std::string Ip4Pdu::toString() const
{
    return "Ip4Pdu";
}
*/
