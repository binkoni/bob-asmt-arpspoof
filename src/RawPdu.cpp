#include <boost/format.hpp>
#include <iostream>
#include <sstream>
#include "Pdu.h"
#include "RawPdu.h"

RawPdu::RawPdu():
    Pdu{}
{
}

/*
void RawPdu::print(std::stringstream& sstr) const
{
    sstr << RawPdu::toString();
}

std::string RawPdu::toString() const
{
    return "";
}
*/
