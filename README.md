# eCPPTv2
eCPPTv2 Preparation Notes

# Information Gathering

## Whois Lookup

###### Query information from domain:
```
whois <domain>
```

###### Use a different whois server:
```
whois -h <server> <domain>
```

## DNS

###### Performs a basic DNS Query:
```
nslookup <target>
```

###### List mail exchange servers for a given domain:
```
nslookup -query=mx <domain>
```

###### List nameservers:
```
nslookup -query=ns <domain>
```

###### List all information:
```
nslookup -query=any <domain>
```

###### Returns mails server within specified domain:
```
dig +nocmd <domain> MX +noall +answer
```

###### Query the A records:
```
dig +nocmd <domain> A +noall +answer
```

###### Returns name servers within specified domain:
```
dig +nocmd <domain> NS +noall +answer
```

###### Attempts a zone transfer from specified name server:
```
dig +nocmd axfr <@name_server> <domain> +noall +answer
```

###### Automates domain enumeration. Performs zone transfer, subdomain brute force, and more:
```
fierce -dns <domain> --dnsserver <server>
```

###### Attempts to brute forces subdomains of specified domain:
```
dnsmap <domain>
```

###### List A, NS, MX and mapping ip adresses in one scan:
```
dnsrecon -d <domain>
```

###### Automates domain enumeration:
```
dnsenum <domain>
```

# Host Discovery with Fping Hping Nmap

###### Before a SYN scan with wihtout arp ping:
```
nmap -sn <target> --disable-arp-ping
```

###### Before a SYN scan with wihtout arp ping and with TCP packet with a SYN flag attached:
```
nmap -sn -PS <target> --disable-arp-ping
```

###### Before a SYN scan with wihtout arp ping and with TCP packet with a ACK flag attached:
```
nmap -sn -PA <target> --disable-arp-ping
```

###### Before a SYN scan with wihtout arp ping and with TCP packet with ICMP echo request:
```
nmap -sn -PE <target> --disable-arp-ping
```

###### Send ICMP echo request packets and only display hosts that are alive:
```
fping -A <target>
```

###### Send ICMP echo request packets and only display hosts that are alive and specify the number of retries (-r):
```
fping -A <target> -r <number of retries>
```

###### Specify a range of ip addresses such as a whole subnet (-g), send ICMP packets to every host in subnet, display time required to reach host (-e) and force fping to be quiet (-q):
```
fping -q -a -g <target> <subnet to scan> -r 0 -e
```

# Scanning

## Hping

###### Perform a SYN scan for range of ports:
```
hping3 -S -p <port> <target>
```

###### Specify a port range:
```
hping3 -S --scan 1-1000 <target>
```

###### SYN scan all ports:
```
hping3 -S --scan all <target>
```

###### SYN scan a list of ports:
```
hping3 -S --scan 80,445,53,21 <target>
```

## Nmap

###### Simple SYN scan:
```
nmap -sS <target>
```

###### Increase scan speed by disabling DNS resolution -n and treating parget as online -Pn:
```
nmap -sS <target> -n -Pn 
```

###### Execute TCP connect scan -sT in fast mode -F which scans fewer ports than the default scan:
```
nmap -sT <target> -F
```

###### Scan UDP ports:
```
nmap -sU <target>
```

###### TCP null scan:
```
nmap -sN <target>
```

###### Christmas scan:
```
nmap -sX <target>
```

###### FIN scan:
```
nmap -sF <target>
```

# Nmap NSE

###### NSE scripts are located in:
```
/usr/share/nmap/scripts/
```

###### Execute default set of scripts:
```
nmap -c
```

###### Specify certain script:
```
nmap --script 
```

###### How to update scripts:
```
nmap --script-updatedb
```

###### Get help for certain script catagory (example help for SMB discovery scripts):
```
nmap --script-help “smb*” and discovery
```

###### Lookup whois information:
```
nmap --script whois-domain <website> -sn
```

###### SMB OS discovery:
```
nmap --script smb-os-discovery -p 445 <target>
```

###### Enumerate all SMB shares:
```
nmap --script smb-enum-shares <target> -p 445
```

###### Execute all authentication related scripts:
```
nmap --script auth <target>
```

# Idle Scan Hping Nmap

**Idle scan is stealthy because the target host will never know the real attacker's ip**

###### Probes a zombie candidate:
```
hping3 -S -r -p <port> <zombie_ip>
```

###### Spoofs zombie’s IP and probes target:
```
hping3 -a <zombie_ip> -S -p <dst_port> <target>
```

###### Determines if IP ID is incremental:
```
nmap --script ipidseq <target> -p <port>
```

###### Performs Idle scan. (performs previous two steps simultaneously):
```
nmap -Pn -sI -p <dst_port> <zombie_ip>:<src_port> <target>
```

# Advanced Port Scanning

###### Fragment packets:
```
nmap -f <target> -n --disable-arp-ping -Pn
```

###### Fragmented SYN scan:
```
nmap -sS -f <target>
```

###### Performs a scan using decoys:
```
nmap -p <port> -D <decoy1,ME,decoy2,etc..> <target>
```

###### Use random number of decays:
```
nmap -D RND:10 <target> -sS -p <port> -Pn --disable-arp-ping
```

###### Port scan using DNS as source port 53:
```
nmap --source-port 53 <target> -sS
```

###### Port scan well known ports using DNS as source port:
```
hping3 -S -s 53 --scan known <target>
```

###### Spoof MAC address (useful if firewall only accepts packets from specific MAC addresses):
```
nmap --spoof-mac <choose vendor MAC i.e. Apple or Intel etc..> <target> -p <port> -Pn --disable-arp-ping -n
```

###### Random MAC address:
```
nmap --spoof-mac 0 <target> -p <port> -Pn --disable-arp-ping -n
```

###### Delayed scan with randomized hosts from a list of hosts:
```
nmap -iL hosts.list -sS -p <port> --randomize-hosts -T 2
```

###### Spoof IP address of alive host:
```
hping3 -a <alive host on network> -S -p <port> <target>
```

###### Evade firewalls that use packet size to detect port scans:
```
nmap -sS --data-length 10 -p 21 <target>
```
