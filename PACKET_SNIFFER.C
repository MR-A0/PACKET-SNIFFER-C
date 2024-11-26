#include <stdio.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <ctype.h>
#include <netinet/if_ether.h>

void print_ascii_art() {
    // This is the ASCII art for "PACKET SNIFFER"
    printf("  PPPP    AAAAA    CCCCC   K   K   EEEEE   TTTTT      SSS     N   N   III   FFFFF    FFFFF  EEEEE   RRRR  \n");
    printf("  P   P   A   A   C        K  K    E         T       S        NN  N    I    F        F      E       R   R \n");
    printf("  PPPP    AAAAA   C        KKK     EEEE      T       SSS      N N N    I    FFFF     FFFF   EEEE    RRRR  \n");
    printf("  P       A   A   C        K  K    E         T          S     N  NN    I    F        F      E       R  R  \n");
    printf("  P       A   A    CCCCC   K   K   EEEEE     T       SSS      N   N   III   F        F      EEEEE   R   R \n");

    printf("\n\n\n");
    printf("----------------------------------------------------------\n\n");
    printf("                   PACKET SNIFFER                        \n\n");
    printf("----------------------------------------------------------\n\n");
}
void callback_packet_h_f(unsigned char* user_passed_data, const struct pcap_pkthdr* Ppkthdr, const unsigned char* DataC_Packet){
    static int udp_count = 0, tcp_count = 0, icmp_count = 0, other_count = 0; // fpr cpunting how mcuh packet we capture of protocols
    pcap_t* p_t_handle = (pcap_t*)user_passed_data; // after passing this p_t_handle through pcap_loop in main function now we are retriving data of packet capture session in void funct.
    //This retrieves the pcap_t handle passed as user_data in pcap_loop().
    //Essentially, it restores access to the packet capture session within the callback function.
    
    printf("-------------------------------PACKET DATA CAPTURED----------------------------- \n\n");
    printf("CAPTURED PACKET LENGTH: %d BYTES.\n\n", Ppkthdr->len); //It prints the captured packet's length using the len field from pcap_pkthdr
    
    int data_link_l_type = pcap_datalink(p_t_handle);
    if(data_link_l_type == DLT_EN10MB){
        if (Ppkthdr->len >= sizeof(struct ether_header)) {
            struct ether_header* PTether_header = (struct ether_header*)DataC_Packet;

            printf("SOURCE MAC IN HEX : ");
            for (int j = 0; j < 6; ++j){
                printf("%02x",PTether_header->ether_shost[j]);
                if (j<5){
                    printf(":");
                }

            }
            printf("\n\n");
            
            printf("SOURCE MAC IN BINARY: ");

            for (int j = 0; j < 6; ++j) {
                for (int bit = 7; bit >= 0; --bit) {
                    printf("%d", (PTether_header->ether_shost[j] >> bit) & 1);  // Extract each bit using bitwise shift and AND operation
                                                    }
                    if (j < 5) {
                        printf(":");
                                }
                                        }
            printf("\n\n");

///////////////////////////////DESTINANTION///////////////////////////

            printf("DESTINATION MAC IN HEX :");
             for (int j = 0; j < 6; ++j){
                printf("%02x",PTether_header->ether_dhost[j]);
                if (j<5){
                    printf(":");
                }

            }
            printf("\n\n");
                        
            printf("DESTINATION MAC IN BINARY: ");

            for (int j = 0; j < 6; ++j) {
                for (int bit = 7; bit >= 0; --bit) {
                    printf("%d", (PTether_header->ether_dhost[j] >> bit) & 1);  // Extract each bit using bitwise shift and AND operation
                                                    }
                    if (j < 5) {
                        printf(":");
                                }
                                        }
            printf("\n\n");

        }
    }

    //WE ARE CHECKING PACKET IS LONG ENOUGH FOR THE IP HEADER 
    if(Ppkthdr-> len >=(sizeof(struct ether_header) + sizeof(struct ip))){
        struct ip* PTip_header = (struct ip*)(DataC_Packet + sizeof(struct ether_header));
                    
        printf("IP Protocol: %d\n\n", PTip_header->ip_p);  // This will show if it's TCP (6) or UDP (17)
        //printing source and destinantion ip
        printf("SOURCE IP: %s\n\n", inet_ntoa(PTip_header->ip_src));
        printf("DESTINATION IP: %s\n\n", inet_ntoa(PTip_header->ip_dst));


       // Handle different protocols
        if (PTip_header->ip_p == IPPROTO_TCP) {
            tcp_count++;
            if (Ppkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr))) {
                struct tcphdr* PTtcp_header = (struct tcphdr*)(DataC_Packet + sizeof(struct ether_header) + (PTip_header->ip_hl * 4));

                printf("Detected: TCP Packet\n\n");
                printf("SOURCE PORT : %d\n\n", ntohs(PTtcp_header->th_sport));
                printf("DESTINATION PORT : %d\n\n", ntohs(PTtcp_header->th_dport));
            }
        }
        else if (PTip_header->ip_p == IPPROTO_UDP) {
            udp_count++;
            if (Ppkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr))) {
                struct udphdr* PTudp_header = (struct udphdr*)(DataC_Packet + sizeof(struct ether_header) + PTip_header->ip_hl * 4);
                printf("Detected: UDP Packet\n\n");
                printf("SOURCE PORT : %d\n\n", ntohs(PTudp_header->uh_sport));
                printf("DESTINATION PORT : %d\n\n", ntohs(PTudp_header->uh_dport));
            }
        }
        else if (PTip_header->ip_p == IPPROTO_ICMP) {
            icmp_count++;
            printf("Detected: ICMP Packet\n\n");
        }
        else {
            other_count++;
            printf("Detected: Other IP Protocol\n\n");
        }
    }
    
    //DISCPLAY PACKET DATA IN HEX ITS DISPLAY 
    printf("PACKET DATA (HEX) : \n\n");
    for(int j =0; j < Ppkthdr->len; ++j){
        printf("%02x ", DataC_Packet[j]);
        if (j % 8 == 0) printf("\n");

    }
    printf("\n");

    // DISPLAY PACKET IN ASCII FORMAT 
    for (int j = 0; j < Ppkthdr->len; ++j){
        char a = DataC_Packet[j];
        if(isprint(a)) {
            printf("%c", a);

        }
        else {
            printf("..");
        }
        
    }
    printf("\n\nPACKETS END!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n");
    printf("TCP: %d, UDP: %d, ICMP: %d, Other: %d\n", tcp_count, udp_count, icmp_count, other_count);
}
int main(int argc, char* argv[]){
    print_ascii_art();
    char* dev;

    if (argc >= 2) {
        printf("-----------------------YOUR PROGRAM NAME------------------------: %s\n\n",argv[0]);
        printf("-----------------------YOUR INTERFACE NAME------------------------: %s\n\n",argv[1]);

        dev = argv[1];  // inside of dev your network interface. this is the device write on command line 


        struct ifaddrs* p_t_ifaddrs;
        struct sockaddr_in* p_t_sockaddr_in;

        if(getifaddrs(&p_t_ifaddrs) == 0){
            for (struct ifaddrs* ptifa = p_t_ifaddrs; ptifa != NULL; ptifa = ptifa->ifa_next){
                if(ptifa->ifa_addr != NULL && ptifa->ifa_addr->sa_family == AF_INET){
                    struct sockaddr_in* addr = (struct sockaddr_in*)ptifa->ifa_addr;

                    if(strcmp(ptifa->ifa_name,dev) == 0){
                        printf("--------------YOUR IP----------ON%s:%s \n",ptifa->ifa_name, inet_ntoa(addr->sin_addr));

                    }
                }

           } 

            freeifaddrs(p_t_ifaddrs);
        } 
        else{
            fprintf(stderr,"FAILED TO GET IP IP ADDRESS FROM SYSTEM WITH getifaddrs()\n");

        }

    }
    else{
        printf("---------------------------------------PLEASE GIVE COMMAND LINE ARGUMENTS-----------------------------------------------");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p_t_handle;

    pcap_if_t* allinterface;
    if(pcap_findalldevs(&allinterface, errbuf) == -1){
        fprintf(stderr,"ERROR IN FINDING NETWORK INTERFACES ON SYSTEM: %s \n", errbuf);
        return 1;

    }

    p_t_handle = pcap_open_live(dev,99536,1,1000,errbuf);
    if(p_t_handle == NULL){

        fprintf(stderr," SRY COULD NOT OPEN DEVICE %s: %s\n",dev,errbuf);
        pcap_freealldevs(allinterface);
        return 1;


    }
    
    // EVERY TIME PACKET CAPTURE PCAP_LOOP GIVE CALL BACK TO callback_packet_h_f
    pcap_loop(p_t_handle,0,callback_packet_h_f,(unsigned char*)p_t_handle); // we are passing p_t_handle as a user data to call back function for retriving in callback function
    struct pcap_stat stats;
    if (pcap_stats(p_t_handle, &stats) == 0) {
    printf("Packets received: %d\n", stats.ps_recv);
    printf("Packets dropped: %d\n", stats.ps_drop);
}
    pcap_close(p_t_handle);
    pcap_freealldevs(allinterface);

    return 0;


}
