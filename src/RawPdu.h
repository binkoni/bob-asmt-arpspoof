#ifndef RAW_PDU_H
#define RAW_PDU_H

#include <cstdint>
#include <sstream>
#include "Pdu.h"

class RawPdu: public Pdu
{
public:
    explicit RawPdu() = default;
    //virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
