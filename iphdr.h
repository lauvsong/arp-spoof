#pragma once

#include <arpa/inet.h>
#include "ip.h"

struct IpHdr final{
    uint8_t ver_:4;
    uint8_t hlen_:4;
    uint8_t tos_;
    uint16_t tlen_;
    uint16_t id_;
    uint16_t offset_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t checksum_;
    Ip sip_;
    Ip dip_;

    uint16_t tlen() {return ntohs(tlen_);}
};
typedef IpHdr *PIpHdr;
