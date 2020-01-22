#ifndef ETH_PDU_H
#define ETH_PDU_H 

#include <array>
#include <cstdint>
#include <sstream>

#include "MacAddr.h"
#include "Pdu.h"

struct EthHeader
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethtype;
} __attribute__((packed));

class EthPdu: public Pdu
{
public:
    explicit EthPdu();
    explicit EthPdu(const EthHeader& header);
    explicit EthPdu(const EthHeader* header);
    explicit EthPdu(const uint8_t* header);

    MacAddr dmac();
    MacAddr smac();
    uint16_t ethtype();

    void dmac(const MacAddr&);
    void smac(const MacAddr&);
    void ethtype(uint16_t);

    MacAddr dmac() const;
    MacAddr smac() const;
    uint16_t ethtype() const;

    /*
    virtual void print(std::stringstream& sstr) const override;
    */
    virtual std::string toString() const override;
};

#endif
