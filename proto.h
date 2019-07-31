#define MY_NTOHS(n) ((uint16_t)((n & 0x00ff) << 8 | (n & 0xff00) >> 8))
#define MY_NTOHL(n) ((uint16_t)((n & 0x000000ff) << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | (n & 0xff000000) >> 24))

#define IP_HDR(pkt) ((struct ip_hdr*)((unsigned char*)pkt + sizeof(struct eth_hdr)))
#define TCP_HDR_HLEN(hdr) ((MY_NTOHS((hdr)->hlen_with_flags) & 0b1111000000000000) >> 4)
#define TCP_HDR_FLAGS(hdr) (MY_NTOHS((hdr)->hlen_with_flags) & 0b0000111111111111)
#define TCP_HDR(pkt) ((struct tcp_hdr*)((unsigned char*)IP_HDR(pkt) + ip_hdr->hlen * 4))
#define TCP_PAYLOAD(pkt) ((char*)((unsigned char*)TCP_HDR(pkt) + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt))) * 4))
#define TCP_PAYLOAD_LEN(pkt) (MY_NTOHS(IP_HDR(pkt)->tlen) - (IP_HDR(pkt)->hlen + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt)))) * 4)

struct EthHdr {
  uint8_t dmac[6];
  uint8_t smac[6];
  uint16_t type;
} __attribute__((packed));

struct IpHdr {
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

struct TcpHdr {
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

struct ArpHdr {
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

