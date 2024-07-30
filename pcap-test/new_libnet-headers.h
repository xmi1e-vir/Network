#ifndef SIMPLE_LIBNET_HEADERS_H
#define SIMPLE_LIBNET_HEADERS_H

#include <arpa/inet.h>  // for in_addr structure

// Ethernet header
struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[6]; // destination ethernet address
    uint8_t  ether_shost[6]; // source ethernet address
    uint16_t ether_type;     // protocol
};

// IPv4 header
struct libnet_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4, ip_v:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4, ip_hl:4;
#endif
    uint8_t ip_tos;       // type of service
    uint16_t ip_len;      // total length
    uint16_t ip_id;       // identification
    uint16_t ip_off;      // fragment offset field
    uint8_t ip_ttl;       // time to live
    uint8_t ip_p;         // protocol
    uint16_t ip_sum;      // checksum
    struct in_addr ip_src, ip_dst; // source and destination addresses
};

// TCP header
struct libnet_tcp_hdr {
    uint16_t th_sport;   // source port
    uint16_t th_dport;   // destination port
    uint32_t th_seq;     // sequence number
    uint32_t th_ack;     // acknowledgement number
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4, th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4, th_x2:4;
#endif
    uint8_t  th_flags;
    uint16_t th_win;     // window
    uint16_t th_sum;     // checksum
    uint16_t th_urp;     // urgent pointer
};

#endif  /* SIMPLE_LIBNET_HEADERS_H */
