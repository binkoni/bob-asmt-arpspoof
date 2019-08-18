#ifndef HEADER_H
#define HEADER_H

#include <cstdint>
#include <sstream>
#include <pcap.h>

#define MY_NTOHS(n) ((uint16_t)((n & 0x00ff) << 8 | (n & 0xff00) >> 8))
#define MY_NTOHL(n) ((uint16_t)((n & 0x000000ff) << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | (n & 0xff000000) >> 24))

#define IP_HDR(pkt) ((struct IpPdu*)((uint8_t*)pkt + sizeof(struct EthPdu)))
#define ARP_HDR(pkt) ((struct ArpPdu*)((uint8_t*)pkt + sizeof(struct EthPdu)))

#define TCP_HDR_HLEN(hdr) ((MY_NTOHS((hdr)->hlenWithFlags) & 0b1111000000000000) >> 4)
#define TCP_HDR_FLAGS(hdr) (MY_NTOHS((hdr)->hlenWithFlags) & 0b0000111111111111)
#define TCP_HDR(pkt) ((struct TcpPdu*)((uint8_t*)IP_HDR(pkt) + IpPdu->hlen * 4))
#define TCP_PAYLOAD(pkt) ((char*)((uint8_t*)TCP_HDR(pkt) + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt))) * 4))

#define TCP_PAYLOAD_LEN(pkt) (MY_NTOHS(IP_HDR(pkt)->tlen) - (IP_HDR(pkt)->hlen + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt)))) * 4)

class Pdu
{
protected:
    uint32_t m_rawPduSize;
    uint8_t* m_rawPdu;
public:
    explicit Pdu();
    Pdu(const uint8_t* rawPdu, uint32_t rawPduSize);
    Pdu(uint32_t rawPduSize);
    virtual ~Pdu();
    static Pdu* parse(const uint8_t* rawPdu, uint32_t rawPduSize);
    static Pdu* parseIp(const uint8_t* rawPdu, uint32_t rawPduSize);
    virtual void* header() const;
    virtual size_t headerSize() const;
    virtual std::string toString() const = 0;
    virtual void print(std::stringstream& sstr) const = 0;
    friend std::ostream& operator<<(std::ostream& ostr, const Pdu& packet);
    //void send(pcap_t* handle);
    
};

#endif
