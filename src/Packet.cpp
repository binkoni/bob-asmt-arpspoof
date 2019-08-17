#include <string.h>
#include "Packet.h"

Packet& Packet::operator+=(Header* newHeader)
{
    m_headers.push_back(newHeader);
    m_bufferSize += newHeader->headerStructSize();
    if(m_bufferSize == 0)
    { 
        free(m_buffer);
        m_buffer = nullptr;
    }
    else
    {
        if(m_buffer == nullptr)
            m_buffer = static_cast<unsigned char*>(malloc(m_bufferSize));
        else
            m_buffer = static_cast<unsigned char*>(realloc(m_buffer, m_bufferSize));
    }
    return *this;
}

void Packet::send(pcap_t* handle)
{
    size_t headerOffset = 0;
    for(auto header = m_headers.cbegin(); header != m_headers.cend(); ++header)
    {
        auto headerStruct = (*header)->headerStruct();
        auto headerStructSize = (*header)->headerStructSize();
        memcpy(static_cast<unsigned char*>(m_buffer) + headerOffset, headerStruct, headerStructSize);
        headerOffset += headerStructSize;
    }
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(m_buffer), m_bufferSize) == -2;
}
