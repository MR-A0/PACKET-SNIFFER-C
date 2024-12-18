




1. libpcap must be installed on your system. On Linux, you can install it with:
   
   [ sudo apt-get install libpcap-dev ]

2. Find Your Network Interface : 
   
   [ ifconfig ex: eth0 ]

3. Switch to promiscuous Mode :

   [ sudo ifconfig eth0 promisc ]

4. Compiling :

   [ gcc -Wall -g packet_sniffer.C -o packet_sniffer -lpcap ]

5. Run the program with root privileges to allow access to the network interface :

   [ sudo ./packet_sniffer eth0 ]
  
