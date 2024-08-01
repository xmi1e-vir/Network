#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "new_libnet-headers.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

// 인식 문제로 인해 u_char -> unsigned char
void print_packet_info(const struct pcap_pkthdr* header, const unsigned char* packet) {
    struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP 타입 = 0x0800
        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        
        if (ip->ip_p == IPPROTO_TCP) { // TCP 패킷 확인
            struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip->ip_hl * 4));

            // Ethernet Header의 src mac과 dst mac 출력
            printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->ether_shost[0], eth->ether_shost[1],
                   eth->ether_shost[2], eth->ether_shost[3],
                   eth->ether_shost[4], eth->ether_shost[5]);
            printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->ether_dhost[0], eth->ether_dhost[1],
                   eth->ether_dhost[2], eth->ether_dhost[3],
                   eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP Header의 src ip와 dst ip 출력
            printf("Source IP: %s\n", inet_ntoa(ip->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));

            // TCP Header의 src port와 dst port 출력
            printf("Source Port: %d\n", ntohs(tcp->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp->th_dport));

            // 메시지 데이터 출력 (최대 20바이트)
            int tcp_header_len = (tcp->th_off >> 4) * 4;
            int message_len = header->caplen - sizeof(struct libnet_ethernet_hdr) - (ip->ip_hl * 4) - tcp_header_len;
            int max_message_len = 20;

            if (message_len > 0) {
                printf("Message: ");
                for (int i = 0; i < message_len && i < max_message_len; i++) {
                    printf("%02X ", packet[sizeof(struct libnet_ethernet_hdr) + (ip->ip_hl * 4) + tcp_header_len + i]);
                }
                printf("\n");
            }
            // 보기 편하게 구분하기 위해 추가한 개행문자
            printf("\n");
        }
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
		// 오류로 인해 uchar -> unsigned char
        const unsigned char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        print_packet_info(header, packet);
    }

    pcap_close(pcap);
    return 0;
}
