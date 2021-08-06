#pragma once

#include <cstdio>
#include <thread>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef struct Attacker final {
    Mac mac;
    Ip ip;
} Attacker;

typedef struct Pair final { // flow fix
    int key;    // index
    Mac smac;
    Ip sip;
    Mac tmac;
    Ip tip;
} Pair;

extern Attacker attacker;

void usage();
void get_attacker_info(char* interface);
Mac get_smac(pcap_t* handle, Pair& pair);
Mac get_tmac(pcap_t* handle, Pair& pair);
void infect(pcap_t* handle, Pair& pair);
void relay(pcap_t* handle, u_char* packet, Pair& pair);
bool is_spoofed_ip(const u_char* packet, Pair& pair);
bool is_recover(const u_char* packet, Pair& pair);
void arp_spoof(pcap_t* handle, Pair& pair);
void task(char* dev, Pair& pair);
