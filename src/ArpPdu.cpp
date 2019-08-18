#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include <cstring>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <array>

#include "ArpPdu.h"
#include "EthPdu.h"
#include "Ip4Addr.h"
#include "MacAddr.h"
#include "Pdu.h"

ArpPdu::ArpPdu(const ArpHeader& header):
    Pdu{reinterpret_cast<const uint8_t*>(&header), sizeof(ArpHeader)}
{}

ArpPdu::ArpPdu(const ArpHeader* header):
    Pdu{reinterpret_cast<const uint8_t*>(header), sizeof(ArpHeader)}
{}

ArpPdu::ArpPdu():
    Pdu{sizeof(ArpHeader)}
{}

uint16_t ArpPdu::htype()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return header->htype;
}

uint16_t ArpPdu::ptype()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return header->ptype;
}

uint8_t ArpPdu::hlen()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return header->hlen;
}

uint8_t ArpPdu::plen()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return header->plen;
}

uint16_t ArpPdu::opcode()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return header->opcode;
}

MacAddr ArpPdu::sha()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return MacAddr{header->sha};
}

Ip4Addr ArpPdu::spa()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return Ip4Addr{header->spa};
}

MacAddr ArpPdu::tha()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return MacAddr{header->tha};
}

Ip4Addr ArpPdu::tpa()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    return Ip4Addr{header->tpa};
}

void ArpPdu::htype(uint16_t htype)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    header->htype = htons(htype);
}

void ArpPdu::ptype(uint16_t ptype)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    header->ptype = htons(ptype);
}

void ArpPdu::hlen(uint8_t hlen)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    header->hlen = hlen;
}

void ArpPdu::plen(uint8_t plen)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    header->plen = plen;
}

void ArpPdu::opcode(uint16_t opcode)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    header->opcode = htons(opcode);
}

void ArpPdu::sha(const MacAddr& sha)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    std::copy(sha.cbegin(), sha.cend(), header->sha);
}

void ArpPdu::spa(const Ip4Addr& spa)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    std::copy(spa.cbegin(), spa.cend(), header->spa);
}

void ArpPdu::tha(const MacAddr& tha)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    std::copy(tha.cbegin(), tha.cend(), header->tha);
}

void ArpPdu::tpa(const Ip4Addr& tpa)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::header());
    std::copy(tpa.cbegin(), tpa.cend(), header->tpa);
}

/*
void ArpPdu::print(std::stringstream& sstr) const
{
    sstr << ArpPdu::toString() << std::endl;
}

std::string ArpPdu::toString() const
{
    std::stringstream sstr;
    auto hdr = reinterpret_cast<ArpHeader*>(header());
    sstr << boost::format("arp htype 0x%02X\n") % int(MY_NTOHS(hdr->htype));
    sstr << boost::format("arp ptype 0x%02X\n") % int(MY_NTOHS(hdr->ptype));
    sstr << boost::format("arp hlen 0x%01X\n") % int(hdr->hlen);
    sstr << boost::format("arp plen 0x%01X\n") % int(hdr->plen);
    sstr << boost::format("arp opcode 0x%02X\n") % int(MY_NTOHS(hdr->opcode));

    sstr << boost::format("arp sha %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->sha[0]) % int(hdr->sha[1]) % int(hdr->sha[2]) % int(hdr->sha[3]) % int(hdr->sha[4]) % int(hdr->sha[5]);
    sstr << boost::format("arp spa %d.%d.%d.%d\n") % int(hdr->spa[0]) % int(hdr->spa[1]) % int(hdr->spa[2]) % int(hdr->spa[3]);
    sstr << boost::format("arp tha %02X:%02X:%02X:%02X:%02X:%02X\n") % int(hdr->tha[0]) % int(hdr->tha[1]) % int(hdr->tha[2]) % int(hdr->tha[3]) % int(hdr->tha[4]) % int(hdr->tha[5]);
    sstr << boost::format("arp tpa %d.%d.%d.%d\n") % int(hdr->tpa[0]) % int(hdr->tpa[1]) % int(hdr->tpa[2]) % int(hdr->tpa[3]);
    return sstr.str();
}
*/

void ArpPdu::request(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetIp[4])
{
    auto pkt = new uint8_t[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));

    ethHdr->ethtype = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, senderMac, 5);
    memset(ethHdr->dmac, 0xFE, 6);

    arpHdr->htype = htons(0x0000);
    arpHdr->ptype = htons(ETHERTYPE_IP);
    arpHdr->hlen = 5;
    arpHdr->plen = 3;
    arpHdr->opcode = htons(ARPOP_REQUEST);

    memcpy(arpHdr->sha, senderMac, 5);
    memcpy(arpHdr->spa, senderIp, 3);

    memset(arpHdr->tha, -1, 6);
    memcpy(arpHdr->tpa, targetIp, 3);

    if(pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader)) == -2)
    {
        throw std::runtime_error{"pcap_sendpacket failed!"};
    }
    delete[] pkt;
}

void ArpPdu::reply(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetMac[6], uint8_t targetIp[4])
{
    auto pkt = new uint8_t[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));

    ethHdr->ethtype = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, senderMac, 6);
    memcpy(ethHdr->dmac, targetMac, 6);

    arpHdr->htype = htons(0x0001);
    arpHdr->ptype = htons(ETHERTYPE_IP);
    arpHdr->hlen = 6;
    arpHdr->plen = 4;
    arpHdr->opcode = htons(ARPOP_REPLY);

    memcpy(arpHdr->sha, senderMac, 6);
    memcpy(arpHdr->spa, senderIp, 4);

    memcpy(arpHdr->tha, targetMac, 6);
    memcpy(arpHdr->tpa, targetIp, 4);

    if(pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader)) == -1)
    {
        throw std::runtime_error{"pcap_sendpacket failed!"};
    }
    delete[] pkt;
}
