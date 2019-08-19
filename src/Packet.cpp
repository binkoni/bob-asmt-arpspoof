#include <algorithm>
#include <string>
#include <memory>
#include <pcap.h>
#include "Packet.h"

Packet::Packet() {}

void Packet::resizeBuffer(const Pdu& newPdu)
{
    m_buffer.resize(m_buffer.size() + newPdu.headerSize());
}

Packet& Packet::operator<<(std::unique_ptr<Pdu>&& newpdu)
{
    Packet::resizeBuffer(*newpdu);
    m_pdus.push_back(std::move(newpdu));
    return *this;
}

void Packet::send(pcap_t* handle)
{
    size_t pduOffset = 0;
    for(auto pdu = m_pdus.cbegin(); pdu != m_pdus.cend(); ++pdu)
    {
        auto header = static_cast<uint8_t*>((*pdu)->header());
        auto headerSize = (*pdu)->headerSize();
        std::copy_n(header, headerSize, std::begin(m_buffer) + pduOffset);
        pduOffset += headerSize;
    }
    pcap_sendpacket(handle, m_buffer.data(), m_buffer.size()); // == -2;
}