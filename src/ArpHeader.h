#ifndef ARP_HEADER_H 
#define ARP_HEADER_H

#include <array>
#include <cstdint>
#include <sstream>
#include <pcap.h>
#include "Header.h"

struct ArpHeaderStruct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed));

class ArpHeader: public Header
{
public:
    static void request(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetIp[4]);
    static void reply(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetMac[6], uint8_t targetIp[4]);
    explicit ArpHeader(const ArpHeaderStruct* headerStruct);
    explicit ArpHeader();

    void htype(uint16_t);
    void ptype(uint16_t);
    void hlen(uint8_t);
    void plen(uint8_t);
    void opcode(uint16_t);
    void sha(std::array<uint8_t, 6>);
    void spa(std::array<uint8_t, 4>);
    void tha(std::array<uint8_t, 6>);
    void tpa(std::array<uint8_t, 4>);

    virtual std::string toString() const override;
    virtual void print(std::stringstream& sstr) const override;
    //void send(pcap_t* handle);
};

#endif
