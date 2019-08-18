#include <string.h>
#include "Packet.h"

void Packet::resizeBuffer(const Pdu& newPdu)
{
    m_buffer.resize(m_buffer.size() + newPdu->headerSize())
    m_buffer = static_cast<uint8_t*>(realloc(m_buffer, m_bufferSize));
}

Packet& Packet::operator+=(const Pdu& newPdu)
{
    Packet::resizeBuffer(newPdu);
    m_pdus.push_back(newPdu);
    return *this;
}

packet& packet::operator+=(pdu&& newpdu)
{
    packet::resizebuffer(newpdu);
    m_pdus.push_back(std::move(newpdu));
    return *this;
}

void Packet::send(pcap_t* handle)
{
    size_t pduOffset = 0;
    for(auto pdu = m_pdus.cbegin(); pdu != m_pdus.cend(); ++pdu)
    {
        auto header = static_cast<uint8_t*>(pdu->header());
        auto headerSize = pdu->headerSize();
        std::copy_n(header, headerSize, std::begin(m_buffer) + pduOffset);
        pduOffset += headerSize;
    }
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(m_buffer), m_bufferSize) == -2;
}
