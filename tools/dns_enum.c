#include "dns_enum.h"
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
#include <pthread.h>

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define RESET   "\033[0m"

pthread_mutex_t mutex;

typedef struct {
    char domain[256];
    char subdomain[256];
    char ip[INET_ADDRSTRLEN];
} thread_data_t;


void *check_subdomain_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int result = check_subdomain(data->domain, data->subdomain, data->ip);
    pthread_mutex_lock(&mutex);
    if (result) {
        printf(GREEN "[+] Subdomain found: %s.%s (%s)" RESET "\n", data->subdomain, data->domain, data->ip);
    } else {
        //printf(RED "[-] Subdomain not found: %s.%s" RESET "\n", data->subdomain, data->domain);
    }
    pthread_mutex_unlock(&mutex);
    free(data);
    return NULL;
}

int format_dns_name(const char* domain , unsigned char* dns_format) {
    const char* start = domain;
    const char* end = strchr(start, '.');
    int pos = 0;

    while (end) {
        int len = end - start;
        dns_format[pos++] = len;
        memcpy(dns_format + pos, start, len);
        pos += len;
        start = end + 1;
        end = strchr(start, '.');
    }

    int len = strlen(start);
    dns_format[pos++] = len;
    memcpy(dns_format + pos, start, len);
    pos += len;
    dns_format[pos] = 0; // Null-terminate the DNS format
    return pos + 1; // Total length of the formatted name
}

int send_dns_query(const char* dns_server, const unsigned char* dns_query, int query_len, char* ip_str) {
    struct sockaddr_in server_addr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53); // DNS port
    if (inet_pton(AF_INET, dns_server, &server_addr.sin_addr) <= 0) {
        close(sock);
        return 0;
    }

    struct timeval timeout;
    sendto(sock, dns_query, query_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    timeout.tv_sec = 5; // 5 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    unsigned char buffer[512];
    socklen_t addr_len = sizeof(server_addr);
    int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &addr_len);
    close(sock);
    if (recv_len < 0) {
        return 0;
    }

    // Process the response
    dns_header_t* response_header = (dns_header_t*)buffer;
    uint16_t response_flags = ntohs(response_header->flags);
    int rcode = response_flags & 0x000F; // Extract RCODE

    if (rcode == 0) {
        unsigned char * ip_ptr = buffer + query_len; // Start of the answer section
        int answer_count = ntohs(response_header->ans_count);
        for (int i = 0; i < answer_count; i++) {
            // Skip the name
            ip_ptr += 2; 
            uint16_t type = ntohs(*(uint16_t*)ip_ptr);
            ip_ptr += 8; // Skip type, class,TLL
            uint16_t data_len = ntohs(*(uint16_t*)ip_ptr);
            ip_ptr += 2; // Move to the RDATA
            if (type == 1 && data_len == 4) { // A record
                inet_ntop(AF_INET, ip_ptr, ip_str, INET_ADDRSTRLEN);
                return 1; // Subdomain exists
            }
            ip_ptr += data_len; // Move to the next answer
        }
        return 0; // No A record found, subdomain may not exist
    }
    return 0; // Non-zero RCODE indicates an error or non-existence
}

int check_subdomain(const char* domain, const char* subdomain, char* ip_str) {
    char dns_query[512];
    unsigned char dns_format[512];
    char full_domain[512];
    snprintf(full_domain, sizeof(full_domain), "%s.%s", subdomain, domain);
    int format_len = format_dns_name(full_domain, dns_format);

    // Create a DNS query packet
    dns_header_t header;
    memset(&header, 0, sizeof(header));
    header.id = htons(rand() % 65536); // Random ID
    header.q_count = htons(1); // One question
    header.flags = htons(0x0100); // Standard query, Recursion desired

    dns_question_t question;
    question.qtype = htons(1); // A record
    question.qclass = htons(1); // IN class

    memcpy(dns_query, &header, sizeof(header));
    memcpy(dns_query + sizeof(header), dns_format, format_len);
    memcpy(dns_query + sizeof(header) + format_len, &question, sizeof(question));

    int query_len = sizeof(header) + format_len + sizeof(question);
    int result = send_dns_query("8.8.8.8", (unsigned char*)dns_query, query_len, ip_str);
    
    return result;
}

int dns_enumerate(const char* domain, const char* wordlist_path, int thread_count) {

    if (wordlist_path == NULL) {
        wordlist_path = "subdomains.txt"; // Default wordlist
    }

    if (thread_count <= 0) {
        thread_count = 15; // Default thread count
    }

    FILE* wordlist = fopen(wordlist_path, "r");
    if (!wordlist) {
        perror("fopen");
        return 0;
    }

    pthread_mutex_init(&mutex, NULL);
    pthread_t threads[thread_count];
    int thread_index = 0;

    char subdomain[256];
    while (fgets(subdomain, sizeof(subdomain), wordlist)) {
        subdomain[strcspn(subdomain, "\n")] = 0; // Remove newline

        thread_data_t* data = malloc(sizeof(thread_data_t));
        strncpy(data->domain, domain, sizeof(data->domain));
        strncpy(data->subdomain, subdomain, sizeof(data->subdomain));

        pthread_create(&threads[thread_index++], NULL, check_subdomain_thread, data);

        if (thread_index >= thread_count) {
            for (int i = 0; i < thread_index; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_index = 0;
        }
    }

    // Join any remaining threads
    for (int i = 0; i < thread_index; i++) {
        pthread_join(threads[i], NULL);
    }

    fclose(wordlist);
    pthread_mutex_destroy(&mutex);
    return 1;
    
}