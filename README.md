# PACKET-SNIFFER

![MY Image](https://github.com/MR-A0/PACKET-SNIFFER-C/blob/c19d8685ebfe263dde7cda20fa031a7c9611f7a4/Screenshot%202024-12-18%20121042.png)


# Requirement:

libpcap must be installed on your system. On Linux, you can install it with:

[ sudo apt-get install libpcap-dev ]

Find Your Network Interface :

[ ifconfig ex: eth0 ]

Switch to promiscuous Mode :

[ sudo ifconfig eth0 promisc ]

Compiling : [OPTIONAL]

[ gcc -Wall -g packet_sniffer.C -o packet_sniffer -lpcap ]

Run the program with root privileges to allow access to the network interface :

[ sudo ./packet_sniffer eth0 ]
