#ifndef HEADER_H
#define HEADER_H

#include <cstdint>
#include <sstream>
#include <pcap.h>

#define MY_NTOHS(n) ((uint16_t)((n & 0x00ff) << 8 | (n & 0xff00) >> 8))
#define MY_NTOHL(n) ((uint16_t)((n & 0x000000ff) << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | (n & 0xff000000) >> 24))

#define IP_HDR(pkt) ((struct IpHeader*)((unsigned char*)pkt + sizeof(struct EthHeader)))
#define ARP_HDR(pkt) ((struct ArpHeader*)((unsigned char*)pkt + sizeof(struct EthHeader)))
#define TCP_HDR_HLEN(hdr) ((MY_NTOHS((hdr)->hlenWithFlags) & 0b1111000000000000) >> 4)
#define TCP_HDR_FLAGS(hdr) (MY_NTOHS((hdr)->hlenWithFlags) & 0b0000111111111111)
#define TCP_HDR(pkt) ((struct TcpHeader*)((unsigned char*)IP_HDR(pkt) + IpHeader->hlen * 4))
#define TCP_PAYLOAD(pkt) ((char*)((unsigned char*)TCP_HDR(pkt) + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt))) * 4))
#define TCP_PAYLOAD_LEN(pkt) (MY_NTOHS(IP_HDR(pkt)->tlen) - (IP_HDR(pkt)->hlen + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt)))) * 4)

class Header
{
protected:
    uint32_t m_rawHeaderLen;
    unsigned char* m_rawHeader;
public:
    explicit Header();
    Header(const unsigned char* rawHeader, uint32_t rawHeaderLen);
    Header(uint32_t rawHeaderLen);
    virtual ~Header();
    static Header* parse(const unsigned char* rawHeader, uint32_t rawHeaderLen);
    static Header* parseIp(const unsigned char* rawHeader, uint32_t rawHeaderLen);
    virtual void* headerStruct() const;
    virtual std::string toString() const = 0;
    virtual void print(std::stringstream& sstr) const = 0;
    friend std::ostream& operator<<(std::ostream& ostr, const Header& packet);
    //void send(pcap_t* handle);
    
};

#endif
