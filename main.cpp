#include "my-func.h"

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 == 1) {
        usage();
        return -1;
    }

    setbuf(stdout, NULL);
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    pcap_close(handle); // to thread tasks

    // get attacker info
    get_attacker_info(dev);
    printf("Attacker IP: %s\n", std::string(attacker.ip).c_str());
    printf("Attacker MAC: %s\n", std::string(attacker.mac).c_str());

    // threads
    int pair_cnt = (argc-2)/2;
    Pair pairs[pair_cnt];
    std::thread tasks[pair_cnt];

    // allocate thread per pair
    int idx = 0;
    for (int i=2;i<argc;i+=2){
        pairs[idx].key = idx;
        pairs[idx].sip =Ip(argv[i]);
        pairs[idx].tip= Ip(argv[i+1]);

        tasks[idx] = std::thread(task, dev, std::ref(pairs[idx]));
        ++idx;
    }

    // thread tasks
    for (int i=0;i<idx;i++){
        tasks[i].join();
    }
    return 0;
}
