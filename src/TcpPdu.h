#ifndef TCP_PDU_H
#define TCP_PDU_H

#include <cstdint>
#include <sstream>
#include <arpa/inet.h>
#include "Pdu.h"

struct TcpHeader {
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

class TcpPdu: public Pdu
{
public:
    explicit TcpPdu(const TcpHeader& header);
    explicit TcpPdu();
    #define TCP_PDU_HLEN(header) ((ntohs((header)->hlenWithFlags) & 0b1111000000000000) >> 4)
    #define TCP_PDU_FLAGS(header) (ntohs((header)->hlenWithFlags) & 0b0000111111111111)
    /*
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
    */
};

#endif
