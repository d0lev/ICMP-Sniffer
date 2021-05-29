#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h> 
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#define PACKET_SIZE 65536


// credit to : https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

const char *icmp_types[] = {"Echo Reply","Unassigned","Unassigned","Destination Unreachable",
                            "Source Quench","Redirect","Alternate Host Address","Unassigned",
                            "Echo","Router Advertisement","Router Selection","Time Exceeded"};



int handle_packet(const uint8_t *packet_buffer,uint16_t packet_length) {
    //the first bytes of the packet is the ethernet header
    struct ethhdr* ethernet_header = (struct ethhdr*) packet_buffer;
    // //check if the packet protocol is ip usnig ntohs to convert big endian to little endian
    if(ntohs(ethernet_header->h_proto) == ETH_P_IP) {
        //extract the ip header from the ethernet header
        struct iphdr* ip_header =  (struct iphdr*)(packet_buffer + sizeof(struct ethhdr));
        // check if the protocol ip is ICMP
        if(ip_header->protocol == 1) {
        struct sockaddr_in src_ip = {0};
        src_ip.sin_addr.s_addr = ip_header->saddr; // the source address from the sending packet
        char source_ip_str[MAX_IPOPTLEN] = {0};
        strcpy(source_ip_str,inet_ntoa(src_ip.sin_addr));
    
        struct sockaddr_in dest_ip = {0};
        dest_ip.sin_addr.s_addr = ip_header->daddr; // the destination address from the sending packet
        char destination_ip_str[MAX_IPOPTLEN] = {0};
        strcpy(destination_ip_str,inet_ntoa(dest_ip.sin_addr));

        //get the icmp header from the ip header
        unsigned short ip_header_length = ip_header->ihl * 4;
        struct icmphdr* icmp_header = (struct icmphdr*)(packet_buffer + sizeof(struct ethhdr) + ip_header_length);
        uint type = (unsigned int) (icmp_header->type);
        uint code = (unsigned int) (icmp_header->code);
        if(type < 11) {
        printf("Source IP : %s    Destination IP : %s   TYPE:  %s CODE: %u\n",source_ip_str,destination_ip_str,icmp_types[type],code);
        }
        }
    }
     return 0;
}

int main(int argc , char* argv[]) {

    int error_code = 0;
    ssize_t data_size; //uint that can initialize with -1
    uint8_t packet_buffer[PACKET_SIZE] = {0};
    if(argc != 2){
        printf("Usage: %s [IFNAME]\n",argv[0]);
        error_code = 1;
        goto cleanup;
    }

    const char* interface_name = argv[1];
    //ETH_P_ALL - we sniffing all the packets from any type
    int raw_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(raw_socket == -1) {
        perror("failed to create a socket");
        error_code = 2;
        goto cleanup;
    }
    if(setsockopt(raw_socket,SOL_SOCKET,SO_BINDTODEVICE,interface_name,strlen(interface_name)) == -1) {
        perror("setsockopt");
        error_code = 2;
        goto cleanup;
    }    

    for (;;) {
        data_size = recvfrom(raw_socket,packet_buffer,PACKET_SIZE,0,NULL,NULL);
        if(data_size == -1) {
            perror("recvfrom");
            error_code = 3;
            goto cleanup;
        }
       handle_packet(packet_buffer,data_size);
       bzero(packet_buffer,PACKET_SIZE);
    
    }


cleanup:
    if(raw_socket != -1 && close(raw_socket) == -1) {
        perror("failed to close the socket");
    }
    return error_code;


}
