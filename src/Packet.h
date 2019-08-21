#ifndef PACKET_H
#define PACKET_H

#include <array>
#include <memory>
#include <vector>
#include "Pdu.h"

class Packet
{
private:
    std::vector<std::unique_ptr<Pdu>> m_pdus; 
    std::vector<uint8_t> m_buffer;
public:
    explicit Packet() = default;
    void resizeBuffer(const Pdu& newPdu);
    Packet& operator<<(std::unique_ptr<Pdu>&& newpdu);
    void send(pcap_t* handle);
};

#endif
