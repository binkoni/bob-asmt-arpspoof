#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include "UnknownHeader.h"
#include "Header.h"

UnknownHeader::UnknownHeader():
    Header{}
{
}

void UnknownHeader::print(std::stringstream& sstr) const
{
    sstr << UnknownHeader::toString();
}

std::string UnknownHeader::toString() const
{
    return "";
}
