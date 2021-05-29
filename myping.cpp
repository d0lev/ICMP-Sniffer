#include <stdio.h>
#include <unistd.h>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <cstring>
#include <iostream>

// IPv4 header len without options
#define IP4_HDRLEN 20
// ICMP header len for echo req
#define ICMP_HDRLEN 8

// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

// Checksum algorithm
unsigned short calculate_checksum(unsigned short *paddress, int len);

int main() {
    struct icmp icmphdr; // ICMP-header

    //ICMP_ECHO is equal to 8 which means this a echo request.
    icmphdr.icmp_type = ICMP_ECHO;
    icmphdr.icmp_code = 0;
    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18;
    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;
    // Combine the packet
    char packet[IP_MAXPACKET];
    // ICMP header.
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;

    // ICMP data.
    memcpy(packet + ICMP_HDRLEN, &data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)packet, ICMP_HDRLEN + datalen);
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    socklen_t len = sizeof(dest_in);
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket for IP-ICMP
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){perror("failed to create a socket");}

    struct timeval start, end;
    gettimeofday(&start, NULL);

    // Send the packet using sendto() for sending Datagrams.
    int byteSend = sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
    if (byteSend == -1) {perror("failed to send a message");}

    printf("Successfuly send one packet : ICMP HEADER : %d bytes} data length : %d , icmp header : %d \n\n", byteSend, datalen, ICMP_HDRLEN);


    int bytesRecv = -1;
    for(;;) {
        bytesRecv = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_in, &len);
        if (bytesRecv > 0){break;}
        perror("failed to recive the packet");
        }

    printf("Successfuly receive one packet with %d bytes : data length : %d , icmp header : %d , ip header : %d \n\n", bytesRecv, datalen, ICMP_HDRLEN,IP4_HDRLEN);

    gettimeofday(&end, NULL);


    // second > milliseconds (10^(-3) seconds) > microseconds (10^(-6) seconds)
    float milliseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
    unsigned long microseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec);
    printf("RTT time in milliseconds: %f \n", milliseconds);
    printf("RTT time in microseconds: %ld\n\n", microseconds);

    // Close the raw socket descriptor.
    close(sock);

    return 0;
}



unsigned short calculate_checksum(unsigned short *paddress, int len){
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1){
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1){
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}