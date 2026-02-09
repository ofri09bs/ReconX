#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include "utils.h"


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
            timeout.tv_sec = 1; // 1 seconds timeout
            timeout.tv_usec = 0;

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


int scan_top_ports(const char *ip) {
    char service[64];
    for (int port = 1; port <= 1024; port++) {
        if (scan_port(ip, port, service) == 0) {
            printf("%d/tcp OPEN %s\n", port, service);
        }
        else {
            printf("%d/tcp %s\n", port, service);
        }

    }
    return 0;
}