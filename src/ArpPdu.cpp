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
#include "Packet.h"
#include "Pdu.h"

ArpPdu::ArpPdu()
{
    Pdu::parse(sizeof(ArpHeader));
}

ArpPdu::ArpPdu(const ArpHeader& header)
{
    Pdu::parse(reinterpret_cast<const uint8_t*>(&header), sizeof(ArpHeader));
}

ArpPdu::ArpPdu(const ArpHeader* header)
{
    Pdu::parse(reinterpret_cast<const uint8_t*>(header), sizeof(ArpHeader));
}

ArpPdu::ArpPdu(const uint8_t* header)
{
    Pdu::parse(header, sizeof(ArpHeader));
}

uint16_t ArpPdu::htype()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return header->htype;
}

uint16_t ArpPdu::ptype()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return ntohs(header->ptype);
}

uint8_t ArpPdu::hlen()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return header->hlen;
}

uint8_t ArpPdu::plen()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return header->plen;
}

uint16_t ArpPdu::opcode()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return ntohs(header->opcode);
}

MacAddr ArpPdu::sha()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return MacAddr{header->sha};
}

Ip4Addr ArpPdu::spa()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return Ip4Addr{header->spa};
}

MacAddr ArpPdu::tha()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return MacAddr{header->tha};
}

Ip4Addr ArpPdu::tpa()
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    return Ip4Addr{header->tpa};
}

void ArpPdu::htype(uint16_t htype)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    header->htype = htons(htype);
}

void ArpPdu::ptype(uint16_t ptype)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    header->ptype = htons(ptype);
}

void ArpPdu::hlen(uint8_t hlen)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    header->hlen = hlen;
}

void ArpPdu::plen(uint8_t plen)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    header->plen = plen;
}

void ArpPdu::opcode(uint16_t opcode)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    header->opcode = htons(opcode);
}

void ArpPdu::sha(const MacAddr& sha)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    std::copy(sha.cbegin(), sha.cend(), header->sha);
}

void ArpPdu::spa(const Ip4Addr& spa)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    std::copy(spa.cbegin(), spa.cend(), header->spa);
}

void ArpPdu::tha(const MacAddr& tha)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    std::copy(tha.cbegin(), tha.cend(), header->tha);
}

void ArpPdu::tpa(const Ip4Addr& tpa)
{
    auto header = reinterpret_cast<ArpHeader* const>(ArpPdu::data());
    std::copy(tpa.cbegin(), tpa.cend(), header->tpa);
}

/*
void ArpPdu::print(std::stringstream& sstr) const
{
    sstr << ArpPdu::toString() << std::endl;
}
*/

std::string ArpPdu::toString() const
{
    std::stringstream sstr;
    auto hdr = static_cast<ArpHeader*>(ArpPdu::data());
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

void ArpPdu::request(pcap_t* handle, const MacAddr& senderMac, const Ip4Addr& senderIp, const Ip4Addr& targetIp)
{
    auto ethPdu = std::make_unique<EthPdu>();
    auto arpPdu = std::make_unique<ArpPdu>();

    ethPdu->ethtype(ETHERTYPE_ARP);
    ethPdu->smac(senderMac);
    ethPdu->dmac(MacAddr{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}});

    arpPdu->htype(0x0000);
    arpPdu->ptype(ETHERTYPE_IP);
    arpPdu->hlen(5);
    arpPdu->plen(3);
    arpPdu->opcode(ARPOP_REQUEST);
    arpPdu->sha(senderMac);
    arpPdu->spa(senderIp);
    arpPdu->tha(MacAddr{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}});
    arpPdu->tpa(targetIp);
    Packet packet{};
    packet << std::move(ethPdu) << std::move(arpPdu);
    packet.send(handle);
}

void ArpPdu::reply(pcap_t* handle, const MacAddr& senderMac, const Ip4Addr& senderIp, const MacAddr& targetMac, const Ip4Addr& targetIp)
{
    auto ethPdu = std::make_unique<EthPdu>();
    auto arpPdu = std::make_unique<ArpPdu>();

    ethPdu->ethtype(ETHERTYPE_ARP);
    ethPdu->smac(senderMac);
    ethPdu->dmac(targetMac);
    arpPdu->htype(0x0001);
    arpPdu->ptype(ETHERTYPE_IP);
    arpPdu->hlen(6);
    arpPdu->plen(4);
    arpPdu->opcode(ARPOP_REPLY);
    arpPdu->sha(senderMac);
    arpPdu->spa(senderIp);
    arpPdu->tha(targetMac);
    arpPdu->tpa(targetIp);
    Packet packet{};
    packet << std::move(ethPdu) << std::move(arpPdu);
    packet.send(handle);
}
