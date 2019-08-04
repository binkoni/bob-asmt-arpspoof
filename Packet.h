#ifndef PACKET_H
#define PACKET_H

#include <cstdint>

#define MY_NTOHS(n) ((uint16_t)((n & 0x00ff) << 8 | (n & 0xff00) >> 8))
#define MY_NTOHL(n) ((uint16_t)((n & 0x000000ff) << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | (n & 0xff000000) >> 24))

#define IP_HDR(pkt) ((struct IpHeader*)((unsigned char*)pkt + sizeof(struct EthHeader)))
#define TCP_HDR_HLEN(hdr) ((MY_NTOHS((hdr)->hlenWithFlags) & 0b1111000000000000) >> 4)
#define TCP_HDR_FLAGS(hdr) (MY_NTOHS((hdr)->hlenWithFlags) & 0b0000111111111111)
#define TCP_HDR(pkt) ((struct TcpHeader*)((unsigned char*)IP_HDR(pkt) + IpHeader->hlen * 4))
#define TCP_PAYLOAD(pkt) ((char*)((unsigned char*)TCP_HDR(pkt) + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt))) * 4))
#define TCP_PAYLOAD_LEN(pkt) (MY_NTOHS(IP_HDR(pkt)->tlen) - (IP_HDR(pkt)->hlen + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt)))) * 4)

enum class PacketType
{
    ETH,
    ARP,
    IP,
    TCP
};

class Packet
{
private:
    unsigned char* m_rawPacket;
    uint32_t m_rawPacketLen;
public:
    explicit Packet();
    explicit Packet(const unsigned char* rawPacket, uint32_t rawPacketLen);
    virtual ~Packet();
    static Packet* parse(const unsigned char* rawPacket, uint32_t rawPacketLen);
    static Packet* parseIp(const unsigned char* rawPacket, uint32_t rawPacketLen);
    virtual std::string toString() = 0;
    friend std::ostream& operator<<(std::ostream& ostr, const Packet& packet);
};

struct EthHeader
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
} __attribute__((packed));

class EthPacket: public Packet
{
    EthHeader* header;
public:
    EthPacket(const unsigned char* rawPacket, uint32_t rawPacketLen);
    std::string toString();
};

struct IpHeader
{
    unsigned char hlen:4;
    unsigned char ver:4;
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t chksum;
    uint8_t sip[4];
    uint8_t dip[4];
} __attribute__((packed));

class IpPacket: public EthPacket
{
    IpHeader* header;
public:
    std::string toString();

};

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

class TcpPacket: public IpPacket
{
    TcpHeader* header;
public:
    std::string toString();

};

struct ArpHeader {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
} __attribute__((packed));

class ArpPacket: public EthPacket
{
    ArpHeader* header;
public:
    ArpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen);
    std::string toString();

};

#endif
