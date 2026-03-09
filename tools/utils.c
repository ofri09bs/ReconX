#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sqlite3.h>
#include "service_grabber.h"

#define DATABASE_PATH "reconx.db"

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

char* get_service_name(int service_type) {
    switch (service_type) {
        case SERVICE_SSH: return "SSH";
        case SERVICE_FTP: return "FTP";
        case SERVICE_SMTP: return "SMTP";
        case SERVICE_POP3: return "POP3";
        case SERVICE_IMAP: return "IMAP";
        case SERVICE_TELNET: return "Telnet";
        case SERVICE_MYSQL: return "MySQL";
        case SERVICE_VNC: return "VNC";
        case SERVICE_HTTP: return "HTTP";
        case SERVICE_HTTPS: return "HTTPS";
        case SERVICE_REDIS: return "Redis";
        case SERVICE_MEMCACHED: return "Memcached";
        case SERVICE_RDP: return "RDP";
        case SERVICE_SMB: return "SMB";
        case SERVICE_POSTGRESQL: return "PostgreSQL";
        case SERVICE_MONGODB: return "MongoDB";
        case SERVICE_LDAP: return "LDAP";
        default: return "Unknown Service";
    }
}

void parse_mac(const char* mac_str, unsigned char* mac_bytes) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
}

int open_socket(const char* ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }
    // Set a timeout for receiving data
    struct timeval timeout;
    timeout.tv_sec = 3; // 5 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    return sockfd;
}


int starts_with(char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

int get_file_line_count(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        return -1;
    }

    int count = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        count++;
    }
    fclose(file);
    return count;
}

unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) > 0;
}

// uses a UDP socket to determine the local IP address by connecting to a public DNS server 
int get_local_ip(const char* target_ip, char* local_ip_buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    inet_pton(AF_INET, target_ip, &serv.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr*)&name, &namelen) < 0) {
        close(sock);
        return -1;
    }

    inet_ntop(AF_INET, &name.sin_addr, local_ip_buffer, INET_ADDRSTRLEN);
    
    close(sock);
    return 0;
}
