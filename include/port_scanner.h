#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct {
    const char* ip;
    const char *local_ip;
    int start_port;
    int end_port;
    int scan_id;
} scan_args_t;

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int scan_port(const char *ip, int port , char *service);
int scan_ports(const char *ip, char *ports , int thread_count, int syn_scan);
void *scan_ports_thread(void *args);
int syn_scan_port(const char *src_ip, const char *dst_ip, int port);
void *syn_scan_ports_thread(void *args);


#endif // PORT_SCANNER_H