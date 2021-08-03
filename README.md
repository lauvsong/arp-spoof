# arp-spoof
advanced arp spoofing

## syntax
```
syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

## function
- spoofed IP packet relay (to target)
- reinfect sender when arp recover
