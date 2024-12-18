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

void print_art(const char *file_name) {
    FILE *file = fopen(file_name, "r");  // Open the file in read mode
    if (file == NULL) {
        perror("[+]\tError opening file");
        return;
    }
    
    char ch;
    while ((ch = fgetc(file)) != EOF) {  // Read character by character
        putchar(ch);  // Print the character to the console
    }

    fclose(file);  // Close the file after reading

    printf("\t\t\t\t$-> BY MR.ANONIM");
    printf("\n\n\n");
}
void callback_packet_h_f(unsigned char* user_passed_data, const struct pcap_pkthdr* Ppkthdr, const unsigned char* DataC_Packet){
    static int udp_count = 0, tcp_count = 0, icmp_count = 0, other_count = 0; // fpr cpunting how mcuh packet we capture of protocols
    pcap_t* p_t_handle = (pcap_t*)user_passed_data; // after passing this p_t_handle through pcap_loop in main function now we are retriving data of packet capture session in void funct.
    //This retrieves the pcap_t handle passed as user_data in pcap_loop().
    //Essentially, it restores access to the packet capture session within the callback function.
    
    printf("\n\033[0;33m[+]\033[0m\tPACKET DATA CAPTURED\n\n");
    printf("\033[0;33m[+]\033[0m\tCAPTURED PACKET LENGTH \033[0;35m->\033[0m \033[0;33m%d\033[0m \033[0;33mBYTES\033[0m\n\n", Ppkthdr->len); //It prints the captured packet's length using the len field from pcap_pkthdr
    
    int data_link_l_type = pcap_datalink(p_t_handle);
    if(data_link_l_type == DLT_EN10MB){
        if (Ppkthdr->len >= sizeof(struct ether_header)) {
            struct ether_header* PTether_header = (struct ether_header*)DataC_Packet;

            printf("\033[0;33m[+]\033[0m\tSOURCE MAC IN HEX \033[0;35m->\033[0m ");
            for (int j = 0; j < 6; ++j){
                printf("\033[0;31m%02x\033[0m",PTether_header->ether_shost[j]);
                if (j<5){
                    printf(":");
                }

            }
            printf("\n\n");
            
            printf("\033[0;33m[+]\033[0m\tSOURCE MAC IN BINARY \033[0;35m->\033[0m ");

            for (int j = 0; j < 6; ++j) {
                for (int bit = 7; bit >= 0; --bit) {
                    printf("\033[0;31m%d\033[0m", (PTether_header->ether_shost[j] >> bit) & 1);  // Extract each bit using bitwise shift and AND operation
                                                    }
                    if (j < 5) {
                        printf(":");
                                }
                                        }
            printf("\n\n");

///////////////////////////////DESTINANTION///////////////////////////

            printf("\033[0;33m[+]\033[0m\tDESTINATION MAC IN HEX \033[0;35m->\033[0m ");
             for (int j = 0; j < 6; ++j){
                printf("\033[0;31m%02x\033[0m",PTether_header->ether_dhost[j]);
                if (j<5){
                    printf(":");
                }

            }
            printf("\n\n");
                        
            printf("\033[0;33m[+]\033[0m\tDESTINATION MAC IN BINARY \033[0;35m->\033[0m ");

            for (int j = 0; j < 6; ++j) {
                for (int bit = 7; bit >= 0; --bit) {
                    printf("\033[0;31m%d\033[0m", (PTether_header->ether_dhost[j] >> bit) & 1);  // Extract each bit using bitwise shift and AND operation
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
                    
        printf("\033[0;33m[+]\033[0m\tIP Protocol \033[0;35m->\033[0m \033[0;31m%d\033[0m\n\n", PTip_header->ip_p);  // This will show if it's TCP (6) or UDP (17)
        //printing source and destinantion ip
        printf("\033[0;33m[+]\033[0m\tSOURCE IP \033[0;35m->\033[0m \033[0;34m%s\033[0m\n\n", inet_ntoa(PTip_header->ip_src));
        printf("\033[0;33m[+]\033[0m\tDESTINATION IP \033[0;35m->\033[0m \033[0;34m%s\033[0m\n\n", inet_ntoa(PTip_header->ip_dst));


       // Handle different protocols
        if (PTip_header->ip_p == IPPROTO_TCP) {
            tcp_count++;
            if (Ppkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr))) {
                struct tcphdr* PTtcp_header = (struct tcphdr*)(DataC_Packet + sizeof(struct ether_header) + (PTip_header->ip_hl * 4));

                printf("\033[0;33m[+]\033[0m\tDetected \033[0;35m->\033[0m TCP Packet\n\n");
                printf("\033[0;33m[+]\033[0m\tSOURCE PORT \033[0;35m->\033[0m \033[0;34m%d\033[0m\n\n", ntohs(PTtcp_header->th_sport));
                printf("\033[0;33m[+]\033[0m\tDESTINATION PORT \033[0;35m->\033[0m \033[0;34m%d\033[0m\n\n", ntohs(PTtcp_header->th_dport));
            }
        }
        else if (PTip_header->ip_p == IPPROTO_UDP) {
            udp_count++;
            if (Ppkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr))) {
                struct udphdr* PTudp_header = (struct udphdr*)(DataC_Packet + sizeof(struct ether_header) + PTip_header->ip_hl * 4);
                printf("\033[0;33m[+]\033[0m\tDetected \033[0;35m->\033[0m UDP Packet\n\n");
                printf("\033[0;33m[+]\033[0m\tSOURCE PORT \033[0;35m->\033[0m \033[0;34m%d\033[0m\n\n", ntohs(PTudp_header->uh_sport));
                printf("\033[0;33m[+]\033[0m\tDESTINATION PORT \033[0;35m->\033[0m \033[0;34m%d\033[0ma\n\n", ntohs(PTudp_header->uh_dport));
            }
        }
        else if (PTip_header->ip_p == IPPROTO_ICMP) {
            icmp_count++;
            printf("\033[0;33m[+]\033[0m\tDetected \033[0;35m->\033 ICMP Packet\n\n");
        }
        else {
            other_count++;
            printf("\033[0;33m[+]\033[0m\tDetected \033[0;35m->\033[0m Other IP Protocol\n\n");
        }
    }
    
    //DISCPLAY PACKET DATA IN HEX ITS DISPLAY 
    printf("\033[0;33m[+]\033[0m\tPACKET DATA (HEX) \033[0;35m->\033[0m \n");
    for(int j =0; j < Ppkthdr->len; ++j){
        if (j % 8 == 0) {
            printf("\n\t");
        }
        printf("\033[0;31m%02x\033[0m ", DataC_Packet[j]);
    }
    printf("\n\n");
    
    // DISPLAY PACKET IN ASCII FORMAT 
    
    printf("\033[0;33m[+]\033[0m\tPACKET DATA (ASCII) \033[0;35m->\033[0m \n");
    printf("\n");
    for (int j = 0; j < Ppkthdr->len; ++j) {
    char a = DataC_Packet[j];
        if (j % 16 == 0) { // Start a new line every 16 bytes
            printf("\n\t\033[0;31m%04x\033[0m  ", j); // Add tabs and print the offset in hexadecimal
        }
        if (isprint(a)) {
        printf("\033[0;31m%c\033[0m", a); // Print printable characters
    }   else {
            printf(".."); // Print '..' for non-printable characters
            }
                                            }
    printf("\n\n\n\033[0;33m[+]\033[0m\tPACKETS END!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n");
    printf("\033[0;33m[+]\033[0m\tTCP \033[0;31m:\033[0m \033[0;33m%d\033[0m, UDP \033[0;31m:\033[0m \033[0;33m%d\033[0m, ICMP \033[0;31m:\033[0m \033[0;33m%d\033[0m, Other \033[0;31m:\033[0m \033[0;33m%d\033[0m\n", tcp_count, udp_count, icmp_count, other_count);
}
int main(int argc, char* argv[]){
    print_art("file.txt");
    char* dev;

    if (argc >= 2) {
        printf("\033[0;33m[+]\033[0m\tYOUR PROGRAM NAME \033[0;35m->\033[0m \033[0;33m%s\033[0m\n\n",argv[0]);
        printf("\033[0;33m[+]\033[0m\tYOUR INTERFACE NAME \033[0;35m->\033[0m \033[0;33m%s\033[0m\n\n",argv[1]);

        dev = argv[1];  // inside of dev your network interface. this is the device write on command line 


        struct ifaddrs* p_t_ifaddrs;
        struct sockaddr_in* p_t_sockaddr_in;

        if(getifaddrs(&p_t_ifaddrs) == 0){
            for (struct ifaddrs* ptifa = p_t_ifaddrs; ptifa != NULL; ptifa = ptifa->ifa_next){
                if(ptifa->ifa_addr != NULL && ptifa->ifa_addr->sa_family == AF_INET){
                    struct sockaddr_in* addr = (struct sockaddr_in*)ptifa->ifa_addr;

                    if(strcmp(ptifa->ifa_name,dev) == 0){
                        printf("\033[0;33m[+]\033[0m\tYOUR IP ON -> \033[0;33m%s\033[0m \033[0;35m:\033[0m \033[0;33m%s\033[0m \n",ptifa->ifa_name, inet_ntoa(addr->sin_addr));

                    }
                }

           } 

            freeifaddrs(p_t_ifaddrs);
        } 
        else{
            fprintf(stderr,"\n\033[0;31m[-]\033[0m\t\t\tFAILED TO GET IP IP ADDRESS FROM SYSTEM WITH getifaddrs()\n");

        }

    }
    else{
        printf("\033[0;31m[-]\033[0m\t\t\tPlease Give your Network interface ex: eth0 , wlan0 , wlan1 [sudo ./name eth0]");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p_t_handle;

    pcap_if_t* allinterface;
    if(pcap_findalldevs(&allinterface, errbuf) == -1){
        fprintf(stderr,"\033[0;31m[-]\033[0m\t\t\tERROR IN FINDING NETWORK INTERFACES ON SYSTEM  \033[0;31m->\033[0m %s \n", errbuf);
        return 1;

    }

    p_t_handle = pcap_open_live(dev,99536,1,1000,errbuf);
    if(p_t_handle == NULL){

        fprintf(stderr,"\033[0;31m[-]\033[0m\t\t\tSRY COULD NOT OPEN DEVICE %s \033[0;31m->\033[0m %s\n",dev,errbuf);
        pcap_freealldevs(allinterface);
        return 1;


    }
    
    // EVERY TIME PACKET CAPTURE PCAP_LOOP GIVE CALL BACK TO callback_packet_h_f
    pcap_loop(p_t_handle,0,callback_packet_h_f,(unsigned char*)p_t_handle); // we are passing p_t_handle as a user data to call back function for retriving in callback function
    struct pcap_stat stats;
    if (pcap_stats(p_t_handle, &stats) == 0) {
    printf("\033[0;33m[+]\033[0m\tPackets received \033[0;31m->\033[0m %d\n", stats.ps_recv);
    printf("\033[0;33m[+]\033[0m\tPackets dropped \033[0;31m->\033[0m %d\n", stats.ps_drop);
}
    pcap_close(p_t_handle);
    pcap_freealldevs(allinterface);

    return 0;


}
