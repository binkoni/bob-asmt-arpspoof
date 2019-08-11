#ifndef ETH_HEADER_H
#define ETH_HEADER_H 

#include <cstdint>
#include <sstream>
#include "Header.h"

struct EthHeaderStruct
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
} __attribute__((packed));

class EthHeader: public Header
{
public:
    explicit EthHeader(EthHeaderStruct* hederStruct);
    EthHeaderStruct* headerStruct() const;
    virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
