#ifndef ARP_PACKET_H
#define ARP_PACKET_H

#include <cstdint>
#include <sstream>
#include <pcap.h>
#include "EthHeader.h"

struct ArpHeaderStruct {
    uint16_t hwtype;
    uint16_t ptype;
    uint8_t hwlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
} __attribute__((packed));

class ArpHeader: public EthHeader
{
public:
    static void request(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetIp[4]);
    static void reply(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetMac[6], uint8_t targetIp[4]);
    explicit ArpHeader(const unsigned char* rawHeader, uint32_t rawHeaderLen);
    explicit ArpHeader();
    ArpHeaderStruct* arpHeaderStruct() const;
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
    void send(pcap_t* handle);
};

#endif