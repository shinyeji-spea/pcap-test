#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>  // for struct in_addr
#include <arpa/inet.h>   // for inet_ntoa()

#define ETHER_ADDR_LEN 6
#define IP_HEADER_LEN 20
#define TCP_HEADER_LEN 20
#define MAX_DATA_LEN 20


struct libnet_packet_hdr {
    // Ethernet Header
    uint8_t  ether_dhost[ETHER_ADDR_LEN]; // destination ethernet address
    uint8_t  ether_shost[ETHER_ADDR_LEN]; // source ethernet address
    uint16_t ether_type;                  // protocol

    // IPv4 Header
    struct in_addr ip_src;                // source IP address
    struct in_addr ip_dst;                // destination IP address

    u_int8_t ip_p;

    // TCP Header
    uint16_t th_sport;                    // source port
    uint16_t th_dport;                    // destination port
};

// MAC 
void print_mac_address(const uint8_t* addr) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
	if (i > 0) {
            printf(":");
        }
        printf("%02x", addr[i]);
    }
    printf("\n");
}

// IP 
void print_ip_address(const struct in_addr* addr) {
    printf("%s\n", inet_ntoa(*addr));
}

// TCP
void print_tcp_ports(uint16_t src_port, uint16_t dst_port) {
    printf("Source Port: %u\n", ntohs(src_port));
    printf("Destination Port: %u\n", ntohs(dst_port));
}

// 데이터 부분
void print_data(const u_char* data, int length) {
    printf("Data (max 20 bytes): ");
    for (int i = 0; i < length && i < MAX_DATA_LEN; i++) {
        if (i > 0) {
            printf(" ");
        }
        printf("%02x", data[i]);
    }
    printf("\n");
}

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
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Ethernet Header 추출
        struct libnet_packet_hdr *eth_hdr = (struct libnet_packet_hdr *)packet;

        // IP Header 오프셋 계산하여 IP 주소 추출
        // IP Header는 Ethernet Header 바로 뒤에 위치
        const u_char *ip_header = packet + sizeof(struct libnet_packet_hdr);
        uint16_t ip_header_len = (ip_header[0] & 0x0F) * 4;
        
        // IP Header + TCP Header 오프셋
        const u_char *tcp_header = ip_header + ip_header_len;
        uint16_t tcp_header_len = (tcp_header[12] >> 4) * 4;
        
        // TCP Header에서 Source Port 및 Destination Port 추출
        uint16_t src_port = ntohs(*(uint16_t *)(tcp_header));
        uint16_t dst_port = ntohs(*(uint16_t *)(tcp_header + 2));

        // 데이터 부분
        const u_char *data = tcp_header + tcp_header_len;
        int data_len = header->caplen - (sizeof(struct libnet_packet_hdr) + ip_header_len + tcp_header_len);
        if (data_len > 0) {
            print_data(data, data_len);
        }
	    
	print_tcp_ports(src_port, dst_port);
	    
        printf("Destination MAC: ");
        print_mac_address(eth_hdr->ether_dhost);

        printf("\nSource MAC: ");
        print_mac_address(eth_hdr->ether_shost);

        printf("Source IP: ");
        print_ip_address(&eth_hdr->ip_src);

        printf("Destination IP: ");
        print_ip_address(&eth_hdr->ip_dst);
    }

    pcap_close(pcap);
}
