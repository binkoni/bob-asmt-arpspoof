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
    static Packet parse(const u_char* data, size_t size);
    explicit Packet() = default;
    void resizeBuffer(const Pdu& newPdu);
    Packet& operator<<(std::unique_ptr<Pdu>&& newpdu);
    std::vector<std::unique_ptr<Pdu>>::iterator begin();
    std::vector<std::unique_ptr<Pdu>>::const_iterator cbegin() const;
    std::vector<std::unique_ptr<Pdu>>::iterator end();
    std::vector<std::unique_ptr<Pdu>>::const_iterator cend() const;
    std::vector<std::unique_ptr<Pdu>>::reverse_iterator rbegin();
    std::vector<std::unique_ptr<Pdu>>::const_reverse_iterator crbegin() const;
    std::vector<std::unique_ptr<Pdu>>::reverse_iterator rend();
    std::vector<std::unique_ptr<Pdu>>::const_reverse_iterator crend() const;

    void send(pcap_t* handle);
};

#endif
