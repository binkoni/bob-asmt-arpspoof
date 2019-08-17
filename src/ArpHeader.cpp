#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include <cstring>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <array>
#include "ArpHeader.h"
#include "EthHeader.h"
#include "Header.h"

ArpHeader::ArpHeader(const ArpHeaderStruct* headerStruct):
    Header{reinterpret_cast<const unsigned char*>(headerStruct), sizeof(ArpHeaderStruct)}
{
}

ArpHeader::ArpHeader():
    Header{sizeof(ArpHeaderStruct)}
{}

void ArpHeader::htype(uint16_t htype)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    headerStruct->htype = htons(htype);
}

void ArpHeader::ptype(uint16_t ptype)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    headerStruct->ptype = htons(ptype);
}

void ArpHeader::hlen(uint8_t hlen)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    headerStruct->hlen = hlen;
}

void ArpHeader::plen(uint8_t plen)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    headerStruct->plen = plen;
}

void ArpHeader::opcode(uint16_t opcode)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    headerStruct->opcode = htons(opcode);
}

void ArpHeader::sha(std::array<uint8_t, 6> sha)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    std::copy(std::begin(sha), std::end(sha), headerStruct->sha);
}

void ArpHeader::spa(std::array<uint8_t, 4> spa)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    std::copy(std::begin(spa), std::end(spa), headerStruct->spa);
}

void ArpHeader::tha(std::array<uint8_t, 6> tha)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    std::copy(std::begin(tha), std::end(tha), headerStruct->tha);
}

void ArpHeader::tpa(std::array<uint8_t, 4> tpa)
{
    auto headerStruct = reinterpret_cast<ArpHeaderStruct*>(ArpHeader::headerStruct());
    std::copy(std::begin(tpa), std::end(tpa), headerStruct->tpa);
}

void ArpHeader::print(std::stringstream& sstr) const
{
    sstr << ArpHeader::toString() << std::endl;
}

std::string ArpHeader::toString() const
{
    std::stringstream sstr;
    auto hdr = reinterpret_cast<ArpHeaderStruct*>(headerStruct());
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

void ArpHeader::request(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetIp[4])
{
    auto pkt = new unsigned char[sizeof(EthHeaderStruct) + sizeof(ArpHeaderStruct)];
    auto ethHdr = reinterpret_cast<EthHeaderStruct*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeaderStruct*>(ARP_HDR(pkt));

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

    if(pcap_sendpacket(handle, pkt, sizeof(EthHeaderStruct) + sizeof(ArpHeaderStruct)) == -2)
    {
        throw std::runtime_error{"pcap_sendpacket failed!"};
    }
    delete[] pkt;
}

void ArpHeader::reply(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetMac[6], uint8_t targetIp[4])
{
    auto pkt = new unsigned char[sizeof(EthHeaderStruct) + sizeof(ArpHeaderStruct)];
    auto ethHdr = reinterpret_cast<EthHeaderStruct*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeaderStruct*>(ARP_HDR(pkt));

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

    if(pcap_sendpacket(handle, pkt, sizeof(EthHeaderStruct) + sizeof(ArpHeaderStruct)) == -1)
    {
        throw std::runtime_error{"pcap_sendpacket failed!"};
    }
    delete[] pkt;
}
