#ifndef PACKET_H
#define PACKET_H

#include <vector>
#include "Pdu.h"

class Packet
{
private:
    std::vector<Pdu> m_pdus; 
    std::vector<uint8_t> m_buffer;
public:
    Packet& operator+=(const Pdu& pdu);
    Packet& operator+=(Pdu&& pdu);
    void send(pcap_t* handle);
};

#endif
