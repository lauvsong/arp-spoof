# arp-spoof
advanced arp spoofing

## syntax
```
syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

## example result
```
Attacker IP: <ATTACKER_IP>
Attacker MAC: <ATTACKER_MAC>
[1] Sender MAC: <sender mac 1>
[1] Target MAC: <target mac 1>
[1] Sender infected!
[1] detect spoofed IP :: relay
[0] Sender MAC: <sender mac 2>
[0] Target MAC: <target mac 2>
[0] Sender infected!
[0] detect spoofed IP :: relay
[1] detect recover :: reinfect
```
- [<number>] means Pair(sender-target) key number


## functions
- send ARP infecting packet
- spoofed IP packet relay (to target)
- reinfect sender when arp recover
- support multiple pair


