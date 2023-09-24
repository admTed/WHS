#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, // IP header length
                       iph_ver:4; // IP version
    unsigned char      iph_tos;   // Type of service
    unsigned short int iph_len;   // IP Packet length (data + header)
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl;   // Time to Live
    unsigned char      iph_protocol; // Protocol type
    unsigned short int iph_chksum; // IP datagram checksum
    struct  in_addr    iph_sourceip; // Source IP address
    struct  in_addr    iph_destip;   // Destination IP address
};

/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used for identifying request
    unsigned short int icmp_seq;    // Sequence number
};

/* UDP Header */
struct udpheader {
    u_int16_t udp_sport; // source port
    u_int16_t udp_dport; // destination port
    u_int16_t udp_ulen;  // udp length
    u_int16_t udp_sum;   // udp checksum
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport; // source port
    u_short tcp_dport; // destination port
    u_int   tcp_seq;   // sequence number
    u_int   tcp_ack;   // acknowledgement number
    u_char  tcp_offx2; // data offset, rsvd
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;   // window
    u_short tcp_sum;   // checksum
    u_short tcp_urp;   // urgent pointer
};

/* Pseudo TCP header */
struct pseudo_tcp {
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[1500];
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) { // Check if it's an IP packet
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("Ethernet Header: src mac: %s, dst mac: %s\n",
               ether_ntoa((struct ether_addr *)eth->ether_shost),
               ether_ntoa((struct ether_addr *)eth->ether_dhost));

        printf("IP Header: src ip: %s, dst ip: %s\n",
               inet_ntoa(ip->iph_sourceip),
               inet_ntoa(ip->iph_destip));

        // Check if it's a TCP packet
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

            printf("TCP Header: src port: %d, dst port: %d\n",
                   ntohs(tcp->tcp_sport),
                   ntohs(tcp->tcp_dport));

            // Calculate message length
            int message_length = header->len - (sizeof(struct ethheader) + (ip->iph_ihl << 2) + TH_OFF(tcp) * 4);

            if (message_length > 0) {
                printf("Message: ");
                for (int i = 0; i < message_length; i++) {
                    printf("%c", packet[sizeof(struct ethheader) + (ip->iph_ihl << 2) + TH_OFF(tcp) * 4 + i]);
                }
                printf("\n");
            } else {
                printf("No Message\n");
            }
        } else {
            printf("Not a TCP packet\n");
        }

        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip"; // Capture only IP packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name ens33 (change to your interface name)
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface: %s\n", errbuf);
        return 1;
    }

    // Step 2: Compile and set the packet filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}
