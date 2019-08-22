#ifndef ARP_HEADER_H 
#define ARP_HEADER_H

#include <array>
#include <cstdint>
#include <sstream>
#include <pcap.h>

#include "Ip4Addr.h"
#include "MacAddr.h"
#include "Pdu.h"

struct ArpHeader {
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

class ArpPdu: public Pdu
{
public:
    static void request(pcap_t* handle, const MacAddr& senderMac, const Ip4Addr& senderIp, const Ip4Addr& targetIp);
    static void reply(pcap_t* handle, const MacAddr& senderMac, const Ip4Addr& senderIp, const MacAddr& targetMac, const Ip4Addr& targetIp);

    explicit ArpPdu(const ArpHeader& header);
    explicit ArpPdu(const ArpHeader* header);
    explicit ArpPdu(const uint8_t* header);
    explicit ArpPdu();

    uint16_t htype();
    uint16_t ptype();
    uint8_t hlen();
    uint8_t plen();
    uint16_t opcode();

    MacAddr sha();
    Ip4Addr spa();
    MacAddr tha();
    Ip4Addr tpa();

    void htype(uint16_t);
    void ptype(uint16_t);
    void hlen(uint8_t);
    void plen(uint8_t);
    void opcode(uint16_t);

    void sha(const MacAddr&);
    void spa(const Ip4Addr&);
    void tha(const MacAddr&);
    void tpa(const Ip4Addr&);

    virtual std::string toString() const override;
    //virtual void print(std::stringstream& sstr) const override;
};

#endif
