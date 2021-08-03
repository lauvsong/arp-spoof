#pragma once

#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

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

//typedef struct Eth_hdr {

//} Eth_hdr;

//typedef struct Ip_hdr {

//} Ip_hdr;

Attacker attacker;
Sender sender;
Target target;

void usage();
void get_myinfo(char* interface);
Mac get_smac(pcap_t* handle);
void infect_sender(pcap_t* handle);
void relay(pcap_t* handle, u_char* packet);
bool is_spoofed(const u_char* packet);
bool is_recover(const u_char* packet);
void arp_spoof(pcap_t* handle);
