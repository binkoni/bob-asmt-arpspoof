#ifndef PACKET_H
#define PACKET_H

#include <vector>
#include "Header.h"

class Packet
{
private:
    std::vector<Header*> m_headers; 
    unsigned char* m_buffer = nullptr;
    size_t m_bufferSize = 0;
public:
    Packet& operator+=(Header* header);
    void send(pcap_t* handle);
};

#endif
