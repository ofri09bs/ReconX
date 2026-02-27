#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/ethernet.h> 
#include <netinet/ip.h>
#include "lan_sniffer.h"

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

char seen_ips[100][INET_ADDRSTRLEN];
int ip_count = 0;

int is_local_ip(uint32_t ip_addr) {
    unsigned char *bytes = (unsigned char *)&ip_addr;

    if (bytes[0] == 10) return 1; // 10.x.x.x
    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return 1; // 172.16-31.x.x
    if (bytes[0] == 192 && bytes[1] == 168) return 1; // 192.168.x.x
    
    return 0; // External IP or localhost (127.x)
}


void register_and_print_host(char* ip_str, char* mac_str, int ttl) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(seen_ips[i], ip_str) == 0) {
            return; 
        }
    }

    if (strcmp(mac_str, "00:00:00:00:00:00") == 0 || strcmp(mac_str, "ff:ff:ff:ff:ff:ff") == 0) {
        return; 
    }

    if (ip_count >= 100) {
        // clear buffer if we reach the limit
        ip_count = 0;
        memset(seen_ips, 0, sizeof(seen_ips));
    }

    strncpy(seen_ips[ip_count], ip_str, INET_ADDRSTRLEN);
    ip_count++;

    // Simple OS fingerprinting based on TTL values
    char* os_guess = "Unknown OS";
    if (ttl <= 64) {
        os_guess = "Linux / macOS";
    } else if (ttl <= 128) {
        os_guess = "Windows";
    } else {
        os_guess = "Router / Appliance";
    }

    printf(GREEN "[+] New Host:" RESET YELLOW " %-15s | MAC: %s | OS: %s\n" RESET, ip_str, mac_str, os_guess);
}

// set the network interface to promiscuous mode to capture all traffic (not just traffic destined for the host)
void set_promiscuous_mode(int sockfd, const char* iface) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1); // copy interface name
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}


void start_lan_sniffer(const char* iface) {
    int sockfd;
    unsigned char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    // Create a raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    set_promiscuous_mode(sockfd, iface);

    printf("Listening for LAN traffic on interface %s...\n", iface);

    while (1) {
        ssize_t data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        struct ether_header *eth = (struct ether_header *)buffer;
        
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ether_header));

            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            char src_mac[18];
            char dst_mac[18];

            inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);

            snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                     eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
                     
            snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                     eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            if (is_local_ip(ip->saddr)) {
                register_and_print_host(src_ip, src_mac, ip->ttl);
            }
            if (is_local_ip(ip->daddr)) {
                register_and_print_host(dst_ip, dst_mac, ip->ttl); 
            }
        }
    }

    close(sockfd);
}