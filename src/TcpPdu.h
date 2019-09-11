#ifndef TCP_PDU_H
#define TCP_PDU_H

#include <cstdint>
#include <sstream>
#include <arpa/inet.h>
#include "Pdu.h"

#define TCP_PDU_HLEN(header) ((ntohs((header)->hlen_flags) & 0b1111000000000000) >> 4)
#define TCP_PDU_FLAGS(header) (ntohs((header)->hlen_flags) & 0b0000111111111111)

struct TcpHeader {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint16_t hlen_flags;
    uint16_t winsize;
    uint16_t chksum;
    uint16_t urgptr;
    uint8_t options[40];
} __attribute__((packed));

class TcpPdu: public Pdu
{
public:
    explicit TcpPdu();
    explicit TcpPdu(const TcpHeader& header);
    explicit TcpPdu(const TcpHeader* header);
    explicit TcpPdu(const uint8_t* header);

    uint16_t sport() const;
    uint16_t dport() const;
    uint32_t seqnum() const;
    uint32_t acknum() const;
    uint8_t hlen() const;
    uint16_t flags() const;
    uint16_t winsize() const;
    uint16_t chksum() const;
    uint16_t urgptr() const;
    std::array<uint8_t, 8> options() const;

    //virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const override;
};

#endif
