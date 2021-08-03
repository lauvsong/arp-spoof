#pragma once

#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef struct Attacker {
    Mac mac;
    Ip ip;
} Attacker;

typedef struct Sender {
    Mac mac;
    Ip ip;
} Sender;

typedef struct Target {
    Mac mac;
    Ip ip;
} Target;

Attacker attacker;
Sender sender;
Target target;

void usage();
void get_myinfo(char* interface);
Mac get_smac(pcap_t* handle);
void attack(pcap_t* handle);
