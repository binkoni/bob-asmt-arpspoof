#include <algorithm>
#include <string>
#include <memory>
#include <pcap.h>
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
