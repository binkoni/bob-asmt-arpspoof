#include <pcap.h>
#include <cstring>
#include <iostream>
#include "proto.h"

void print_EthHdr(const struct EthHdr* hdr) {
  std::printf("eth dmac %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->dmac[0], hdr->dmac[1], hdr->dmac[2], hdr->dmac[3], hdr->dmac[4], hdr->dmac[5]);
  std::printf("eth smac %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->smac[0], hdr->smac[1], hdr->smac[2], hdr->smac[3], hdr->smac[4], hdr->smac[5]);
  std::printf("eth type 0x%04x\n", MY_NTOHS(hdr->type));
}

void print_IpHdr(const struct IpHdr* hdr) {
  std::printf("ip ver %u\n", hdr->ver);
  std::printf("ip hlen %u\n", hdr->hlen);
  std::printf("ip type of service 0x%x\n", hdr->tos);
  std::printf("ip tlen %u\n", MY_NTOHS(hdr->tlen));
  std::printf("ip id 0x%x(0x%x)\n", MY_NTOHS(hdr->id), hdr->id);
  std::printf("ip flags 0x%x\n", MY_NTOHS(hdr->flags));
  std::printf("ip ttl %u\n", hdr->ttl);
  std::printf("ip proto 0x%x\n", hdr->proto);
  std::printf("ip chksum 0x%x\n", MY_NTOHS(hdr->chksum));
  std::printf("ip src %d.%d.%d.%d\n", hdr->sip[0], hdr->sip[1], hdr->sip[2], hdr->sip[3]);
  std::printf("ip dst %d.%d.%d.%d\n", hdr->dip[0], hdr->dip[1], hdr->dip[2], hdr->dip[3]);
}

void print_TcpHdr(const struct TcpHdr* hdr) {
  std::printf("tcp sport: %u\n", MY_NTOHS(hdr->sport));
  std::printf("tcp dport: %u\n", MY_NTOHS(hdr->dport));
  std::printf("tcp seq: %x\n", MY_NTOHL(hdr->seqNum));
  std::printf("tcp ack: %x\n", MY_NTOHL(hdr->ackNum));
  std::printf("tcp hlenWithFlags 0x%x\n", hdr->hlenWithFlags);
  std::printf("tcp hlen: 0x%x\n", MY_NTOHS(TCP_HDR_HLEN(hdr)));
  std::printf("tcp flags: 0x%x\n", TCP_HDR_FLAGS(hdr));
  std::printf("tcp wsize: 0x%x\n", hdr->wsize);
  std::printf("tcp chksum: 0x%x\n", hdr->chksum);
  std::printf("tcp urgPtr: 0x%x\n", hdr->urgPtr);
}

int print_pkt(pcap_t* handle) {
  struct pcap_pkthdr* pkt_info;
  const u_char* pkt;
  int res = pcap_next_ex(handle, &pkt_info, &pkt);
  if(res != 1)
    return res;
  const struct EthHdr* EthHdr = (struct EthHdr*)pkt;
  if(MY_NTOHS(EthHdr->type) == 0x0800) {
    const struct IpHdr* IpHdr = IP_HDR(pkt);
    if(IpHdr->proto == 0x06) {
      const struct TcpHdr* TcpHdr = TCP_HDR(pkt);
      #ifdef HTTP
      if(TCP_HDR_FLAGS(TcpHdr) == 0x018 && (MY_NTOHS(TcpHdr->dport) == 80 || MY_NTOHS(TcpHdr->sport) == 80)) {
      #endif
        print_EthHdr(EthHdr);
        print_IpHdr(IpHdr);
        print_TcpHdr(TcpHdr);
        uint16_t payload_len = TCP_PAYLOAD_LEN(pkt);
        std::cout << "tcp payload len " << payload_len << std::endl;
        std::cout << std::endl << "----------------------------------" << std::endl;;
        #ifndef HTTP
          if(payload_len > 10)
            payload_len = 10;
        #endif
        for(uint16_t i = 0; i != payload_len; ++i)
          std::cout << *(TCP_PAYLOAD(pkt) + i);
        std::cout << std::endl << "----------------------------------" << std::endl;;
      #ifdef HTTP
      }
      #endif
    }
  }
  return res;
}

int main(int argc, char** argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  if(argc < 2) {
    #ifdef HTTP
    std::cout << "pcap test (HTTP only: true)" << std::endl;
    #else
    std::cout << "pcap test (HTTP only: false)" << std::endl;
    #endif
    std::cout << "Usage: " << argv[0] << " <dev>" << std::endl;
    std::cout << "Available Devices" << std::endl;
    pcap_if_t* alldevsp;
    pcap_findalldevs(&alldevsp, errbuf);
    if(alldevsp != NULL) {
      for(pcap_if_t* curdevp = alldevsp; curdevp->next != NULL; curdevp = curdevp->next)
        std::cout << "  " << curdevp->name << std::endl;
    }
    std::exit(EXIT_FAILURE);
  }
  pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
  if(handle == NULL) {
    std::cout << errbuf << std::endl;
    return -1;
  }
  while(true) {
    int res = print_pkt(handle);
    if(res == 0)
      continue;
    if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
      break;
  }
  pcap_close(handle);
}
