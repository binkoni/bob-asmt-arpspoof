#ifndef IP4_ADDR_H
#define IP4_ADDR_H

#define IP4_ADDR_SIZE 4

class Ip4Addr
{
private:
    std::array<uint8_t, IP4_ADDR_SIZE> m_addr;
public:
    Ip4Addr(const struct sockaddr& sockAddr);
    Ip4Addr(const char* str);
    Ip4Addr(std::string string);
    Ip4Addr(uint32_t num);
    Ip4Addr(uint8_t arr[IP4_ADDR_SIZE]);
    Ip4Addr(std::array<uint8_t, IP4_ADDR_SIZE> arr);

    std::array<uint8_t, IP4_ADDR_SIZE>::iterator begin();
    std::array<uint8_t, IP4_ADDR_SIZE>::const_iterator cbegin() const;
    std::array<uint8_t, IP4_ADDR_SIZE>::iterator end();
    std::array<uint8_t, IP4_ADDR_SIZE>::const_iterator cend() const;
};

#endif
