#ifndef PING_SWEEPER_H
#define PING_SWEEPER_H

#include <stdio.h>
#include <netinet/ip_icmp.h>

typedef struct {
    struct icmphdr hdr;
    char data[56];
} icmp_pkt;

typedef struct {
    char base_ip[16];
    int start_ip;
    int end_ip;
} scan_range_t;

int ping_sweep(const char *target_ip);
void *check_ip_thread(void *arg);
void *scan_range_thread(void *arg);

#endif // PING_SWEEPER_H