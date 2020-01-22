#include <iostream>
#include <cstring>
#include <memory>

#include "Pdu.h"
#include "RawPdu.h"
#include "EthPdu.h"
#include "ArpPdu.h"
#include "Ip4Pdu.h"
#include "TcpPdu.h"

Pdu::Pdu()
{
    m_size = 0;
    m_data = nullptr;
}

void Pdu::parse(const uint8_t* data, size_t size)
{
    m_size = size;
    m_data = static_cast<uint8_t*>(realloc(m_data, m_size));
    std::memcpy(m_data, data, size);
}

void Pdu::parse(size_t size)
{
    m_size = size;
    m_data = static_cast<uint8_t*>(realloc(m_data, m_size));
}

Pdu::~Pdu()
{
    if(m_data != nullptr)
        delete m_data;
}

void* Pdu::data() const
{
    return m_data;
}

size_t Pdu::size() const
{
    return m_size;
}

std::ostream& operator<<(std::ostream& ostr, const Pdu& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
