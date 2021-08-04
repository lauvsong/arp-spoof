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

    // threads
    int pair_cnt = (argc-2)/2;
    Pair pairs[pair_cnt];
    std::thread tasks[pair_cnt];

    // allocate thread per pair
    int idx = 0;
    for (int i=2;i<argc;i+=2){
        pairs[idx].sip =Ip(argv[i]);
        pairs[idx].tip= Ip(argv[i+1]);

        tasks[idx] = std::thread(task, handle, std::ref(pairs[idx]));
        ++idx;
    }

    for (std::thread& task : tasks){
        task.join();
    }

    pcap_close(handle);
    return 0;
}
