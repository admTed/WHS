#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
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
    unsigned char      iph_ttl; // Time to Live
    unsigned char      iph_protocol; // Protocol type
    unsigned short int iph_chksum; // IP datagram checksum
    struct  in_addr    iph_sourceip; // Source IP address
    struct  in_addr    iph_destip;   // Destination IP address
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
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));
            int tcp_header_length = (tcp->th_offx2 >> 4) * 4; // TCP header length

            printf("TCP Header: src port: %d, dst port: %d\n",
                   ntohs(tcp->th_sport),
                   ntohs(tcp->th_dport));

            // Calculate message length
            int message_length = header->len - (sizeof(struct ethheader) + (ip->iph_ihl << 2) + tcp_header_length);

            if (message_length > 0) {
                printf("Message: ");
                for (int i = 0; i < message_length; i++) {
                    printf("%c", packet[sizeof(struct ethheader) + (ip->iph_ihl << 2) + tcp_header_length + i]);
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
