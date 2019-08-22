#include <algorithm>
#include <string>
#include <memory>
#include <iostream>
#include <pcap.h>
#include "RawPdu.h"
#include "EthPdu.h"
#include "ArpPdu.h"
#include "Ip4Pdu.h"
#include "TcpPdu.h"
#include "Packet.h"

void Packet::resizeBuffer(const Pdu& newPdu)
{
    m_buffer.resize(m_buffer.size() + newPdu.size());
}

Packet& Packet::operator<<(std::unique_ptr<Pdu>&& newpdu)
{
    Packet::resizeBuffer(*newpdu);
    m_pdus.push_back(std::move(newpdu));
    return *this;
}

std::vector<std::unique_ptr<Pdu>>::iterator Packet::begin()
{
    return m_pdus.begin();
}

std::vector<std::unique_ptr<Pdu>>::const_iterator Packet::cbegin() const
{
    return m_pdus.cbegin();
}

std::vector<std::unique_ptr<Pdu>>::iterator Packet::end()
{
    return m_pdus.end();
}

std::vector<std::unique_ptr<Pdu>>::const_iterator Packet::cend() const
{
    return m_pdus.cend();
}

/*
Packet Packet::parse(const u_char* data, size_t size)
{
    Packet packet{};
    std::cout << "parse" << std::endl;
    //for(auto pdu = Pdu::parse(data, size); pdu != nullptr; data += pdu->size(), pdu = Pdu::parse(data, size))
    //    packet << std::move(pdu);
    auto pdu = Pdu::parse(data, size);
    std::cout << pdu->toString() << " " << pdu->size() << std::endl;
    
    return packet;
}
*/
Packet Packet::parse(const uint8_t* data, size_t size)
{
    Packet packet{};
    auto ethPdu = std::make_unique<EthPdu>(data);
    const auto ethtype = ethPdu->ethtype();
    packet << std::move(ethPdu);
    switch(ethtype)
    {
        case 0x0800:
            {
                auto ip4Pdu = std::make_unique<Ip4Pdu>(data + sizeof(EthHeader));
                auto proto = ip4Pdu->proto();
                packet << std::move(ip4Pdu);
                if(proto == 0x06)
                    packet << std::make_unique<TcpPdu>(data + sizeof(EthHeader) + ip4Pdu->hlen() * 4);
            }
            break;
        case 0x0806:
            packet << std::make_unique<ArpPdu>(data + sizeof(EthHeader));
            break;
        default:
            packet << std::make_unique<RawPdu>(data, size);
            break;
    }
    /*
    auto ethHeader = reinterpret_cast<const EthHeader*>(data);
    printf("ethtype is %x\n", MY_NTOHS(ethHeader->ethtype));
    switch(MY_NTOHS(ethHeader->ethtype))
    {
        case 0x0800:
            return parseIp(data, size);
        case 0x0806:
            return std::make_unique<ArpPdu>(reinterpret_cast<const ArpHeader*>(data + sizeof(EthHeader)));
        default:
            return std::make_unique<RawPdu>();
    }
    return nullptr;
    */
    return packet;
}
/*
std::unique_ptr<Pdu> Pdu::parseIp(const uint8_t* data, size_t size)
{
    auto ip4Header = reinterpret_cast<const Ip4Header*>(IP_HDR(data));
    if(ip4Header->proto == 0x06)
        return std::make_unique<TcpPdu>(reinterpret_cast<const TcpHeader*>(data + sizeof(EthHeader) + ip4Header->hlen * 4));
    return std::make_unique<RawPdu>();
}
*/
/*
std::ostream& operator<<(std::ostream& ostr, const Pdu& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
*/

void Packet::send(pcap_t* handle)
{
    size_t pduOffset = 0;
    for(auto pdu = m_pdus.cbegin(); pdu != m_pdus.cend(); ++pdu)
    {
        auto header = static_cast<uint8_t*>((*pdu)->data());
        auto headerSize = (*pdu)->size();
        std::copy_n(header, headerSize, std::begin(m_buffer) + pduOffset);
        pduOffset += headerSize;
    }
    if(pcap_sendpacket(handle, m_buffer.data(), m_buffer.size()) == PCAP_ERROR)
        throw std::runtime_error{"PCAP error"};
}
