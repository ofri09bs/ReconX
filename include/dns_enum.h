#ifndef DNS_ENUM_H
#define DNS_ENUM_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct __attribute__((packed)){
    uint16_t id; // Identification
    uint16_t flags; // DNS flags
    uint16_t q_count; // Number of questions
    uint16_t ans_count; // Number of answers
    uint16_t auth_count; // Number of authority records
    uint16_t add_count; // Number of additional records
} dns_header_t;

typedef struct __attribute__((packed)){
    uint16_t qtype; // Query type
    uint16_t qclass; // Query class
} dns_question_t;

void *check_subdomain_thread(void *arg);
int check_subdomain(const char* domain, const char* subdomain, char* ip_str);
int format_dns_name(const char* domain, unsigned char* dns_format);
int send_dns_query(const char* dns_server, const unsigned char* dns_query, int query_len, char* ip_str);
int dns_enumerate(const char* domain, const char* wordlist_path, int thread_count);

#endif // DNS_ENUM_H