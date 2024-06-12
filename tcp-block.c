#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

char host_mac_address[6];
char *dev;
pcap_t* handle;
void get_my_mac_address(const char *iface, uint8_t *mac);
void send_rst_packet(struct ether_header *eth_hdr, struct ip *ip_hdr, struct tcphdr *tcp_hdr);
void send_fin_packet(struct ether_header *eth_hdr, struct ip *ip_hdr, struct tcphdr *tcp_hdr);
uint16_t csum(uint16_t *buf, int nwords);

struct pseudo_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};


int main(int argc, char **argv){
    setbuf(stdout, NULL);

    if(argc != 3){
        printf("Usage : %s <interface> <pattern>\n", argv[0]);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    dev = argv[1];

    get_my_mac_address(dev, host_mac_address);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while(1){
        struct pcap_pkthdr *header;
        const u_char *org_packet;

        //original packet
        int res = pcap_next_ex(handle, &header, &org_packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        //ethernet type == IPv4
        struct ether_header *eth_hdr = (struct ether_header*)org_packet;
        if(eth_hdr->ether_type != 0x8) continue;

        //IP protocol == TCP
        struct ip *ip_hdr = (struct ip*)(org_packet + ETHER_HDR_LEN);
        if(ip_hdr->ip_p !=  0x6) continue;

        //TCP header & data
        struct tcphdr *tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl << 2));
        if(ntohs(ip_hdr->ip_len) <= (ip_hdr->ip_hl << 2) + (tcp_hdr->th_off << 2)) continue;

        u_char *tcp_data = (u_char*)tcp_hdr + (tcp_hdr->th_off << 2);
        int tcp_data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl << 2) - (tcp_hdr->th_off << 2);

        //Find filter pattern
        struct ether_header *eth_hdr2 = eth_hdr;
        struct ip *ip_hdr2 = ip_hdr;
        struct tcphdr *tcp_hdr2 = tcp_hdr;

        if (tcp_data_len > 0 && memmem(tcp_data, tcp_data_len, argv[2], strlen((char *)argv[2]))) {
            printf("pattern matched!");
            send_rst_packet(eth_hdr, ip_hdr, tcp_hdr);
            send_fin_packet(eth_hdr2, ip_hdr2, tcp_hdr2);
            printf(" - block success\n");
        }

    }
    return 0;
}

void get_my_mac_address(const char *iface, uint8_t *mac){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}


void send_rst_packet(struct ether_header *eth_hdr, struct ip *ip_hdr, struct tcphdr *tcp_hdr){
    memcpy(eth_hdr->ether_shost, host_mac_address, ETHER_ADDR_LEN);

    uint16_t ip_header_size = ip_hdr->ip_hl << 2;
    uint16_t tcp_header_size = tcp_hdr->th_off << 2;
    uint16_t ip_total_len = ip_header_size + tcp_header_size;
    uint16_t tcp_data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl << 2) - (tcp_hdr->th_off << 2);

    if(tcp_hdr->th_flags & TH_FIN){
        ip_total_len += tcp_data_len;
    }
    ip_hdr->ip_len = htons(ip_total_len);
    ip_hdr->ip_sum = csum((uint16_t*)ip_hdr, ip_hdr->ip_hl << 1);

    tcp_hdr->th_flags = TH_RST | TH_ACK;
    tcp_hdr->th_sum = 0;

    struct pseudo_header pseudo_hdr;
    pseudo_hdr.src_ip = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dst_ip = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_length = htons(tcp_header_size);

    uint8_t *buffer = malloc(sizeof(struct pseudo_header) + tcp_header_size);
    memcpy(buffer, &pseudo_hdr, sizeof(struct pseudo_header));
    memcpy(buffer + sizeof(struct pseudo_header), tcp_hdr, tcp_header_size);
    tcp_hdr->th_sum = csum((uint16_t *)buffer, (sizeof(struct pseudo_header) + tcp_header_size) / 2);

    int res = pcap_sendpacket(handle, eth_hdr, ntohs(ip_hdr->ip_len) + ETHER_HDR_LEN);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(buffer);

}

void send_fin_packet(struct ether_header *eth_hdr, struct ip *ip_hdr, struct tcphdr *tcp_hdr){
    int sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        perror("Failed to create socket");
        return;
    }

    uint16_t org_tcp_data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl<<2) - (tcp_hdr->th_off<<2);
    char *http_string = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr/\r\n\r\n";

    memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN); //for lo
    memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN); //for lo

    uint16_t ip_header_size = ip_hdr->ip_hl << 2;
    uint16_t tcp_header_size = tcp_hdr->th_off << 2;
    uint16_t ip_total_len = ip_header_size + tcp_header_size;

    ip_hdr->ip_len = htons(ip_total_len + strlen(http_string));
    uint16_t tcp_data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl<<2) - (tcp_hdr->th_off<<2);

    if (tcp_hdr->th_flags & TH_FIN) {
        ip_total_len += tcp_data_len;
    }

    ip_hdr->ip_ttl = 128;
    struct in_addr temp_ip = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = temp_ip;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = csum((uint16_t *)ip_hdr, ip_hdr->ip_hl << 1);

    uint16_t temp_port = tcp_hdr->th_sport;
    tcp_hdr->th_sport = tcp_hdr->th_dport;
    tcp_hdr->th_dport = temp_port;

    uint32_t temp = tcp_hdr->th_ack;
    tcp_hdr->th_ack = htonl(ntohl(tcp_hdr->th_seq) + org_tcp_data_len);
    tcp_hdr->th_seq = temp;

    tcp_hdr->th_flags =  TH_ACK | TH_FIN;
    tcp_hdr->th_sum = 0;

    struct pseudo_header pseudo_hdr;
    pseudo_hdr.src_ip = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dst_ip = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_length = htons(tcp_header_size + tcp_data_len);

    uint8_t *buffer = malloc(sizeof(struct pseudo_header) + tcp_header_size + tcp_data_len);
    memcpy(buffer, &pseudo_hdr, sizeof(struct pseudo_header));
    memcpy(buffer + sizeof(struct pseudo_header), tcp_hdr, tcp_header_size);
    memcpy(buffer + sizeof(struct pseudo_header) + tcp_header_size, http_string, tcp_data_len);
    tcp_hdr->th_sum = csum((uint16_t *)buffer, (sizeof(struct pseudo_header) + tcp_header_size + tcp_data_len) / 2);


    free(buffer);

    // Set the destination address
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex = if_nametoindex("lo");
    memcpy(sa.sll_addr, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    sa.sll_halen = ETHER_ADDR_LEN;

    uint8_t *fin_packet = malloc(ntohs(ip_hdr->ip_len) + ETHER_HDR_LEN);
    memcpy(fin_packet, eth_hdr, ntohs(ip_hdr->ip_len) + ETHER_HDR_LEN - strlen(http_string));
    memcpy(fin_packet + ntohs(ip_hdr->ip_len) + ETHER_HDR_LEN - strlen(http_string), http_string, strlen(http_string));

    if (sendto(sock, fin_packet, ntohs(ip_hdr->ip_len) + ETHER_HDR_LEN, 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0){
        perror("Failed to send RST packet");
    }
    free(fin_packet);
    close(sock);

}

uint16_t csum(uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    while (nwords > 0) {
        sum += *buf++;
        nwords--;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

