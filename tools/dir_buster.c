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


int send_http_request(int sock, const char *path ,const char *ip) {
    char request[2048];
    char *http_request = "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
    snprintf(request, sizeof(request), http_request, path, ip);
    printf("Testing: %s\n", path);
    int bytes_sent = send(sock, request, strlen(request), 0);
    if (bytes_sent < 0) {
        return -1;
    }
    
    char buffer[2048];
    int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        return -1;
    }

    buffer[bytes_received] = '\0';
    if (starts_with(buffer, "HTTP/1.1 2")) {  // Check for 2xx status codes
        return 0;
    }
    return -1;
}

int start_dir_buster(const char *ip, int port, const char *wordlist_path) {
   
    char buffer[1024];

    FILE *file = fopen(wordlist_path, "r"); // open the wordlist file
    if (file == NULL) {
        return -1;
    }

    while(fgets(buffer, sizeof(buffer), file) != NULL) { // read each line from the wordlist

        // open and configure the socket for each request
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock < 0) {
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 300000; // 0.3 seconds timeout

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (result < 0) {
            close(sock);
            continue;
        }

        // Remove newline character if present
        buffer[strcspn(buffer, "\r\n")] = '\0';

        if (strlen(buffer) == 0) {  // Skip empty lines
            close(sock);
            continue;
        }

        int http_result = send_http_request(sock, buffer, ip); // sends HTTP request
        if (http_result == 0) {
            printf("%s:%d/%s - Found\n", ip, port, buffer);
        }
        close(sock);
    }

    fclose(file);
    return 0;
}