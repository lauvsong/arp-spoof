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
    resolve_attacker_info(dev);
    printf("Attacker IP: %s\n", std::string(attacker.ip).c_str());
    printf("Attacker MAC: %s\n", std::string(attacker.mac).c_str());

    // threads
    int flow_cnt = (argc-2)/2;
    Flow flows[flow_cnt];
    std::thread tasks[flow_cnt];

    // allocate thread per pair
    int idx = 0;
    for (int i=2;i<argc;i+=2){
        flows[idx].key = idx;
        flows[idx].sip =Ip(argv[i]);
        flows[idx].tip= Ip(argv[i+1]);

        tasks[idx] = std::thread(task, dev, std::ref(flows[idx]));
        ++idx;
    }

    // thread tasks
    for (int i=0;i<idx;i++){
        tasks[i].join();
    }
    return 0;
}
