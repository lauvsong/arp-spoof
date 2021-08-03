#pragma once

#include <arpa/inet.h>
#include "ip.h"

struct IpHdr final{
    uint8_t ver:4;
    uint8_t hlen:4;
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint8_t flag:3;
    uint16_t offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    Ip sip;
    Ip dip;
};
typedef IpHdr *PIpHdr;
