#include "ping_sweeper.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <signal.h>

#define NUM_THREADS 10
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define RESET   "\033[0m"

pthread_mutex_t print_mutex_ping;

void *check_ip_thread(void *arg) {
    char *ip_str = (char *)arg;
    int sockfd;
    struct sockaddr_in dest_addr, recv_addr;
    icmp_pkt icmp_pkt;
    char buffer[1024];

    // Create raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("socket");
        return NULL;
    }

    // Set up destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_str, &dest_addr.sin_addr) != 1) {
        close(sockfd);
        return NULL;
    }

    // Prepare ICMP echo request packet
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    icmp_pkt.hdr.type = ICMP_ECHO;
    icmp_pkt.hdr.code = 0;
    icmp_pkt.hdr.un.echo.id = htons(getpid() & 0xFFFF);
    icmp_pkt.hdr.un.echo.sequence = 1;
    icmp_pkt.hdr.checksum = 0;
    icmp_pkt.hdr.checksum = calculate_checksum(&icmp_pkt, sizeof(icmp_pkt));
    // Send ICMP echo request
    if (sendto(sockfd, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        close(sockfd);
        return NULL;
    }

    // Set timeout for receiving response
    struct timeval timeout = {1, 0}; // 1 second timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Wait for ICMP echo reply
    while (1) {
        socklen_t addr_len = sizeof(recv_addr);
        ssize_t recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);

        if (recv_len <= 0) {
            break;
        }

        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct icmphdr *icmp_reply = (struct icmphdr *)(buffer + ip_header->ihl * 4);
        
        // Checks if:
        // 1. The ICMP type is ECHO REPLY
        // 2. The ICMP ID matches the one we sent (to ensure it's a reply to our request)
        // 3. The source IP of the reply matches the target IP
        if (icmp_reply->type == ICMP_ECHOREPLY && 
            icmp_reply->un.echo.id == htons(getpid() & 0xFFFF) && 
            recv_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr) {

            pthread_mutex_lock(&print_mutex_ping);
            printf(GREEN "[+] %s is alive\n" RESET, ip_str);
            pthread_mutex_unlock(&print_mutex_ping);
            break;

        } else {
            // Not a valid reply, continue waiting
            continue;
        }

    }
    close(sockfd);
    return NULL;
}

void *scan_range_thread(void *arg) {
    scan_range_t *range = (scan_range_t *)arg;
    char base_ip[32];
    strncpy(base_ip, range->base_ip, 32);

    for (int i = range->start_ip; i <= range->end_ip; i++) {
        char target_ip[32];
        snprintf(target_ip, 32, "%s.%d", base_ip, i);
        check_ip_thread(target_ip);
    }
    free(range);
    return NULL;
}

int ping_sweep(const char *target_ip) {

    if (geteuid() != 0) {
    fprintf(stderr, RED "[-] Error: Ping Sweep requires root privileges (run with sudo)\n" RESET);
    return 1;
    }

    char target_ip_copy[32];
    strncpy(target_ip_copy, target_ip, 32);
    char *last_dot = strrchr(target_ip_copy, '.');
    if (last_dot != NULL) {
        *last_dot = '\0'; 
    }

    pthread_t threads[NUM_THREADS];
    pthread_mutex_init(&print_mutex_ping, NULL);

    int ips_per_thread = 254 / NUM_THREADS;

    for (int i = 0; i < NUM_THREADS; i++) {
        int start_ip = i * ips_per_thread + 1;
        int end_ip = (i == NUM_THREADS - 1) ? 254 : (i + 1) * ips_per_thread;

        scan_range_t *range = malloc(sizeof(scan_range_t));
        if (range == NULL) {
            perror("malloc");
            continue;;
        }
        strncpy(range->base_ip, target_ip_copy, 16);
        range->start_ip = start_ip;
        range->end_ip = end_ip;
        if (pthread_create(&threads[i], NULL, scan_range_thread, range) != 0) {
            perror("pthread_create");
            free(range);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&print_mutex_ping);
    return 0;
}