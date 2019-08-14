#ifndef UNKNOWN_HEADER_H
#define UNKNOWN_HEADER_H

#include <cstdint>
#include <sstream>
#include "Header.h"

class UnknownHeader: public Header
{
public:
    explicit UnknownHeader();
    virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
