// Enabled GNU extensions for features like TCP_INFO (just to remove warnings, not strictly necessary for this code)
#define _GNU_SOURCE

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include "utils.h"
#include "port_scanner.h"
#include "db_manager.h"


#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

pthread_mutex_t print_mutex;

int scan_port(const char *ip, int port , char *service) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        snprintf(service, 64, "CLOSED");
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result < 0) {
        if (errno == EINPROGRESS) {
            struct timeval timeout;
            timeout.tv_sec = 0; // 0 seconds
            timeout.tv_usec = 500000; // 0.5 seconds timeout
            
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);

            int select_result = select(sock + 1, NULL, &writefds, NULL, &timeout);

            if (select_result > 0 ){
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error != 0) {
                    close(sock);
                    snprintf(service, 64, "CLOSED");
                    return -1;
                }
            }
            else  {
                close(sock);
                snprintf(service, 64, "CLOSED");
                return -1;
            }
        }
        else {
            close(sock);
            snprintf(service, 64, "CLOSED");
            return -1;
        }
    }

    fcntl(sock, F_SETFL, flags); // Set back to blocking mode

    struct timeval timeout;
    timeout.tv_sec = 2; // 2 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char buffer[2048];
    snprintf(service, 64, "Unknown");
    int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received >= 2) {

        // Check for TLS ClientHello (common in HTTPS)
        unsigned char *ptr = (unsigned char *)buffer;
        if (ptr[0] == 0x16 && ptr[1] == 0x03) {
            snprintf(service, 64, "HTTPS");
        }

        // Null-terminate the buffer
        buffer[bytes_received] = '\0';

        // Check for common service banners that don't require sending data
        if (starts_with(buffer, "SSH-")) {
            snprintf(service, 64, "SSH"); // SSH
        } 
        else if (starts_with(buffer, "220 SMTP")) { // SMTP
            snprintf(service, 64, "SMTP");
        } 
        else if (starts_with(buffer, "220")) { // FTP
            snprintf(service, 64, "FTP");
        }
        else if (starts_with(buffer, "+OK")){ // POP3
            snprintf(service, 64, "POP3");
        }
        else if (starts_with(buffer, "* OK")){ // IMAP
            snprintf(service, 64, "IMAP");
        }
    }
    else {
        // check for HTTP by sending a simple request
        int bytes_sent = send(sock, "HEAD / HTTP/1.0\r\n\r\n", 19, 0);
        if (bytes_sent > 0) {
            bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';

                if (starts_with(buffer, "HTTP/")) {
                    snprintf(service, 64, "HTTP");
                }

            }
            else if (bytes_received == 0) {
                snprintf(service, 64, "Open (Closed by server)");
            }
        }
    }
    close(sock);
    return 0;
}

void *scan_ports_thread(void *args) {
    scan_args_t *scan_args = (scan_args_t *)args;
    char service[64];

    for (int port = scan_args->start_port; port <= scan_args->end_port; port++) {
        if (scan_port(scan_args->ip, port, service) == 0) {
            pthread_mutex_lock(&print_mutex);
            printf(BLUE "%d" RESET "/tcp " GREEN "OPEN" RESET " %s\n", port, service);
            char result_data[256];
            snprintf(result_data, sizeof(result_data), "Port: %d Open, Service: %s", port, service);
            save_scan_result(scan_args->scan_id, result_data, "TCP Connect Scan");
            pthread_mutex_unlock(&print_mutex);
        }
    }
    return NULL;
}

int syn_scan_port(const char *src_ip,const char *dst_ip, int port) {
    int sockdf = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockdf < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, dst_ip, &addr.sin_addr);

    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    struct tcphdr *tcp = (struct tcphdr *)(buffer);
    tcp->source = htons(12345); // Random source port
    tcp->dest = htons(port);
    tcp->seq = htonl(0);
    tcp->ack_seq = 0;
    tcp->doff = 5; // TCP header size

    // flags
    tcp->fin = 0;
    tcp->syn = 1; // SYN flag
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;

    tcp->window = htons(65535);
    tcp->check = 0; // Checksum will be calculated later
    tcp->urg_ptr = 0;

    struct pseudo_header hdr;
    hdr.source_address = inet_addr(src_ip);
    hdr.dest_address = inet_addr(dst_ip);
    hdr.placeholder = 0;
    hdr.protocol = IPPROTO_TCP;
    hdr.tcp_length = htons(sizeof(struct tcphdr));

    int pseudo_packet_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudo_packet = malloc(pseudo_packet_size);

    memcpy(pseudo_packet, (char*)&hdr, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    // Calculate checksum
    tcp->check = calculate_checksum((unsigned short*)pseudo_packet, pseudo_packet_size);
    free(pseudo_packet);

    if (sendto(sockdf, tcp, sizeof(struct tcphdr), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockdf);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 2; 
    tv.tv_usec = 0;
    setsockopt(sockdf, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char recv_buffer[4096];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    
    while (1) {
        int bytes_received = recvfrom(sockdf, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);

        if (bytes_received < 0) {
            close(sockdf);
            return -1;
        }

        struct iphdr *ip = (struct iphdr *)recv_buffer;
        if (ip->protocol == IPPROTO_TCP) {

            struct tcphdr *recv_tcp = (struct tcphdr *)(recv_buffer + ip->ihl * 4);

            if (recv_tcp->source == htons(port) && recv_tcp->dest == htons(12345)) {

                if (recv_tcp->syn && recv_tcp->ack) {
                    close(sockdf);
                    return 0;
                }
                else if (recv_tcp->rst) {
                    close(sockdf);
                    return -1;
                }
            }
        }
    }
    close(sockdf);
    return -1;

}

void *syn_scan_ports_thread(void *args) {
    scan_args_t *scan_args = (scan_args_t *)args;

    for (int port = scan_args->start_port; port <= scan_args->end_port; port++) {
        if (syn_scan_port(scan_args->local_ip, scan_args->ip, port) == 0) {
            pthread_mutex_lock(&print_mutex);
            printf(BLUE "%d" RESET "/tcp " GREEN "OPEN" RESET " Unknown\n", port);
            char result_data[256];
            snprintf(result_data, sizeof(result_data), "Port: %d Open, Service: Unknown", port);
            save_scan_result(scan_args->scan_id, result_data, "SYN Scan");
            pthread_mutex_unlock(&print_mutex);
        }
    }
    return NULL;
}


int scan_ports(const char *ip, char *ports , int thread_count, int syn_scan) {

    int ports_total = 0;
    int start_port_num, end_port_num;

    if (!is_valid_ip(ip)) {
        fprintf(stderr, RED "Invalid IP address format. Please enter a valid IPv4 address.\n" RESET);
        return -1;
    }

    if (ports != NULL && strlen(ports) > 0) {
        char* start_port = strtok(ports, "-"); // getting input like 1-1000
        if (start_port == NULL) {
            fprintf(stderr, RED "Invalid port range format. Use start-end (e.g., 1-1000).\n" RESET);
            return -1;
        }
        char* end_port = strtok(NULL, "");

        start_port_num = atoi(start_port);
        end_port_num = atoi(end_port);
        ports_total = end_port_num - start_port_num + 1;

        if (ports_total <= 0 || end_port_num < start_port_num) {
            fprintf(stderr, RED "Invalid port range. End port must be greater than or equal to start port.\n" RESET);
            return -1;
        }
    }
    else {
        ports_total = 1024; // Default to top 1024 ports if not specified
        start_port_num = 1;
        end_port_num = 1024;
    }

    if (thread_count == 0 || thread_count > ports_total) {
        thread_count = 15; // Default to 15 threads if not specified
    }

    printf("\033[33mPORT\033[0m   \033[33mSTATE\033[0m \033[33mSERVICE\033[0m\n");

    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    int scan_id = create_new_scan(ip, syn_scan ? "SYN Port Scan" : "TCP Connect Scan", timestamp);

    pthread_t threads[thread_count];
    scan_args_t thread_args[thread_count];

    int ports_per_thread = ports_total / thread_count;

    char local_ip[INET_ADDRSTRLEN];
    if (get_local_ip(ip, local_ip) < 0) {
        fprintf(stderr, RED "Failed to determine local IP address.\n" RESET);
        return -1;
    }

    if (syn_scan) {
        for (int i = 0; i < thread_count; i++) {
            thread_args[i].ip = ip;
            thread_args[i].local_ip = local_ip;
            thread_args[i].start_port = start_port_num + (i * ports_per_thread);
            thread_args[i].end_port = (i == thread_count - 1) ? end_port_num : start_port_num + ((i + 1) * ports_per_thread) - 1;
            thread_args[i].scan_id = scan_id;
            pthread_create(&threads[i], NULL, syn_scan_ports_thread, &thread_args[i]);
        }
    }
    else {
        for (int i = 0; i < thread_count; i++) {
            thread_args[i].ip = ip;
            thread_args[i].local_ip = local_ip;
            thread_args[i].start_port = start_port_num + (i * ports_per_thread);
            thread_args[i].end_port = (i == thread_count - 1) ? end_port_num : start_port_num + ((i + 1) * ports_per_thread) - 1;
            thread_args[i].scan_id = scan_id;
            pthread_create(&threads[i], NULL, scan_ports_thread, &thread_args[i]);
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}