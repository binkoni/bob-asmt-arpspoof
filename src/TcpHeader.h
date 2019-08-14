#ifndef TCP_HEADER_H
#define TCP_HEADER_H

#include <cstdint>
#include <sstream>
#include "Header.h"

struct TcpHeaderStruct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqNum;
    uint32_t ackNum;
    uint16_t hlenWithFlags;
    uint16_t wsize;
    uint16_t chksum;
    uint16_t urgPtr;
    uint8_t options[8];
} __attribute__((packed));

class TcpHeader: public Header
{
public:
    explicit TcpHeader(const TcpHeaderStruct* headerStruct);
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
};

#endif
