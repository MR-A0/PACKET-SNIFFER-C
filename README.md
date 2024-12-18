libpcap must be installed on your system. On Linux, you can install it with:

[ sudo apt-get install libpcap-dev ]

Find Your Network Interface :

[ ifconfig ex: eth0 ]

Switch to promiscuous Mode :

[ sudo ifconfig eth0 promisc ]

Compiling :

[ gcc -Wall -g packet_sniffer.C -o packet_sniffer -lpcap ]

Run the program with root privileges to allow access to the network interface :

[ sudo ./packet_sniffer eth0 ]
