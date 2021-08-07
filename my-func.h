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

typedef struct Flow final {
    int key;    // index
    Mac smac;
    Ip sip;
    Mac tmac;
    Ip tip;
} Flow;

extern Attacker attacker;

void usage();
void resolve_attacker_info(char* interface);
Mac resolve_smac(pcap_t* handle, Ip& target);
void infect(pcap_t* handle, Flow& flow);
void relay(pcap_t* handle, u_char* packet, Flow& flow);
bool is_spoofed_ip(const u_char* packet, Flow& flow);
bool is_recover(const u_char* packet, Flow& flow);
void arp_spoof(pcap_t* handle, Flow& flow);
void task(char* dev, Flow& pair);
