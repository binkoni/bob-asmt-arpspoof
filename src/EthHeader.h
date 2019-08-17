#ifndef ETH_HEADER_H
#define ETH_HEADER_H 

#include <array>
#include <cstdint>
#include <sstream>
#include "Header.h"

struct EthHeaderStruct
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethtype;
} __attribute__((packed));

class EthHeader: public Header
{
public:
    explicit EthHeader(const EthHeaderStruct* headerStruct);
    explicit EthHeader();

    std::array<uint8_t, 6> dmac();
    std::array<uint8_t, 6> smac();
    uint16_t ethtype();

    void dmac(std::array<uint8_t, 6>);
    void smac(std::array<uint8_t, 6>);
    void ethtype(uint16_t);

    virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
