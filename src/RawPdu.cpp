#include <boost/format.hpp>
#include <iostream>
#include <sstream>
#include "Pdu.h"
#include "RawPdu.h"

/*
void RawPdu::print(std::stringstream& sstr) const
{
    sstr << RawPdu::toString();
}
*/
RawPdu::RawPdu(const uint8_t* data, size_t size)
{
    Pdu::parse(data, size);
}

std::string RawPdu::toString() const
{
    return "RawPdu";
}
