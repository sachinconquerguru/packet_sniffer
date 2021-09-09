#Write network sniffer tool(It must take input from command line)

#!/usr/bin/python3
print("Use Sudo")

from datetime import datetime 
import sys
import subprocess 
from scapy.all import *

print(sys.argv)

net_iface = sys.argv[1] # taking interface name as command line argument
print(net_iface)

subprocess.call(["ifconfig",net_iface,"promisc"]) 


num_of_pkt = int(sys.argv[2]) # taking no_of_packet as command line
print(num_of_pkt)


time_sec = int(sys.argv[3]) # taking time from command line
print(time_sec)


proto = sys.argv[4] # taking protocol from command line(like all | icmp | arp)
print(proto)

def logs(packet):
	packet.show()
	print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)}")


if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) 
elif proto == "arp" or proto == "icmp":
	sniff(iface = net_iface, count = num_of_pkt,timout = time_sec , prn = logs , filter = proto) 
else:
	print("Wrong protocol")

"""
-------------------------------------------output-----------------------------------------

sudo python3 packet_snifer.py wlp7s0 1 1 all
[sudo] password for sachin: 
Use Sudo
['network_sniffer_commandline.py', 'wlp7s0', '1', '1', 'all']
wlp7s0
1
1
all
###[ Ethernet ]### 
  dst       = 3c:77:e6:e6:3a:07
  src       = bc:8a:e8:07:71:c8
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x28
     len       = 109
     id        = 24027
     flags     = DF
     frag      = 0
     ttl       = 42
     proto     = udp
     chksum    = 0x9d52
     src       = 198.251.204.33
     dst       = 192.168.1.101
     \options   \
###[ UDP ]### 
        sport     = 8801
        dport     = 54912
        len       = 89
        chksum    = 0x4d4e
###[ Raw ]### 
           load      = '\x03\x00\x00\x03\x0f|\xdf\xd3\x86\x00@\xc8\xc7\x01\x05@\xa8\xb3\xac\xbf\x9aT\xc8\xc94\x1b\xd75\x93\x13\xe3\x88\xcc&\xdeyd\x1b\xde\xd97\xd1=\xe0\xf4\xacc\x15\xc3\xcfm5\xa9{W\xb9h\xec&P\x9f\xd9\x92\xb8\x13S\x82}Z$y\x0e\xdf\xd5\xc7\xad\xc2,">\x00'

SRC_MAC: bc:8a:e8:07:71:c8 DEST_MAC: 3c:77:e6:e6:3a:07


"""