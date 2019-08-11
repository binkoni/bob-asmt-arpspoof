#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include <cstring>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "ArpPacket.h"
#include "EthPacket.h"

ArpPacket::ArpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    EthPacket{rawPacket, rawPacketLen}
{
}

ArpHeader* ArpPacket::arpHeader() const
{
    return reinterpret_cast<ArpHeader*>(m_rawPacket + sizeof(EthHeader));
}

void ArpPacket::print(std::stringstream& sstr) const
{
    EthPacket::print(sstr);
    sstr << ArpPacket::toString() << std::endl;
}

std::string ArpPacket::toString() const
{
    std::stringstream sstr;
    auto hdr = arpHeader();
    sstr << boost::format("arp hwtype 0x%02X\n") % int(MY_NTOHS(hdr->hwtype));
    sstr << boost::format("arp ptype 0x%02X\n") % int(MY_NTOHS(hdr->ptype));
    sstr << boost::format("arp hwlen 0x%01X\n") % int(hdr->hwlen);
    sstr << boost::format("arp plen 0x%01X\n") % int(hdr->plen);
    sstr << boost::format("arp opcode 0x%02X\n") % int(MY_NTOHS(hdr->opcode));

    sstr << boost::format("arp smac %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->smac[0]) % int(hdr->smac[1]) % int(hdr->smac[2]) % int(hdr->smac[3]) % int(hdr->smac[4]) % int(hdr->smac[5]);
    sstr << boost::format("arp sip %d.%d.%d.%d\n") % int(hdr->sip[0]) % int(hdr->sip[1]) % int(hdr->sip[2]) % int(hdr->sip[3]);
    sstr << boost::format("arp tmac %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->tmac[0]) % int(hdr->tmac[1]) % int(hdr->tmac[2]) % int(hdr->tmac[3]) % int(hdr->tmac[4]) % int(hdr->tmac[5]);
    sstr << boost::format("arp tip %d.%d.%d.%d\n") % int(hdr->tip[0]) % int(hdr->tip[1]) % int(hdr->tip[2]) % int(hdr->tip[3]);
    return sstr.str();
}

void ArpPacket::request(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetIp[4])
{
    auto pkt = new unsigned char[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));

    ethHdr->type = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, senderMac, 5);
    memset(ethHdr->dmac, 0xFE, 6);

    arpHdr->hwtype = htons(0x0000);
    arpHdr->ptype = htons(ETHERTYPE_IP);
    arpHdr->hwlen = 5;
    arpHdr->plen = 3;
    arpHdr->opcode = htons(ARPOP_REQUEST);

    memcpy(arpHdr->smac, senderMac, 5);
    memcpy(arpHdr->sip, senderIp, 3);

    memset(arpHdr->tmac, -1, 6);
    memcpy(arpHdr->tip, targetIp, 3);


    if(pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader)) == -2)
    {
        throw std::runtime_error{"pcap_sendpacket failed!"};
    }
    delete pkt;
}

void ArpPacket::reply(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetMac[6], uint8_t targetIp[4])
{
    auto pkt = new unsigned char[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));

    ethHdr->type = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, senderMac, 6);
    memcpy(ethHdr->dmac, targetMac, 6);

    arpHdr->hwtype = htons(0x0001);
    arpHdr->ptype = htons(ETHERTYPE_IP);
    arpHdr->hwlen = 6;
    arpHdr->plen = 4;
    arpHdr->opcode = htons(ARPOP_REPLY);

    memcpy(arpHdr->smac, senderMac, 6);
    memcpy(arpHdr->sip, senderIp, 4);

    memcpy(arpHdr->tmac, targetMac, 6);
    memcpy(arpHdr->tip, targetIp, 4);

    if(pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader)) == -1)
    {
        throw std::runtime_error{"pcap_sendpacket failed!"};
    }
    delete pkt;
}