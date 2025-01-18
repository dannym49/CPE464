#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Ethernet Header
struct EthernetHeader{
    unsigned char dest_mac[6];  //Destination MAC address
    unsigned char src_mac[6];   //Source MAC address
    unsigned short type;        //Ethernet type
};

//ARP Header
struct ARPHeader{
    unsigned short hw_type;     //Hardware type  
    unsigned short proto_type;  //Protocol type
    unsigned char hw_size;      //Hardware size
    unsigned char proto_size;   //Protocol size
    unsigned short opcode;      //Operation code
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

//IP Header
struct IPHeader{
    unsigned char version_ihl;  //Version and IHL
    unsigned char tos;          //Type of Service
    unsigned short tot_len;     //Total length
    unsigned short id;          //Identification
    unsigned short flag_fragOffset; //Flags and Fragment Offset
    unsigned char ttl;          //Time to Live
    unsigned char protocol;     //Protocol
    unsigned short checksum;    //Header checksum
    struct in_addr src_ip;
    struct in_addr dest_ip;
};

//ICMP Header
struct ICMPHeader{
    unsigned char type;         //ICMP type
    unsigned char code;         //ICMP code
    unsigned short checksum;    //Checksum
    unsigned short id;          //Identifier
    unsigned short seq_num;     //Sequence number
};
 
//TCP Header
struct TCPHeader{
    unsigned short src_port;    //Source port
    unsigned short dest_port;   //Destination port
    unsigned int seq_num;       //Sequence number
    unsigned int ack_num;       //Acknowledge number
    unsigned char do_rsv_flags; //data offset, reserved bits, flags
    unsigned short window;      //window
    unsigned short checksum;    //checksum
    unsigned short urg_ptr;     //Urgent Pointer
};

//UDP Header
struct UDPHeader{
    unsigned short src_port;    //Source port
    unsigned short dest_port;   //Destination port
    unsigned short length;      //Length
    unsigned short checksum;    //Checksum
};

void parse_ethernet_header(const unsigned char *packet){
    struct EthernetHeader *eth = (struct EthernetHeader *)packet;
    printf("Ethernet Header:\n");
    printf("\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)eth->src_mac));
    printf("\tDestination MAC: %s\n", ehter_ntoa((const struct ether_addr *)eth->dest_mac));
    printf("\tType: 0x%04x\n", ntohs(eth->type));
}

void parse_arp_header(const unsigned char *packet){
    struct ARPHeader *arp = (struct ARPHeader *)packet;
    printf("ARP Header:\n");
    
}