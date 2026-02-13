#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

typedef struct {
    const char* ip;
    int start_port;
    int end_port;
} scan_args_t;

int scan_port(const char *ip, int port , char *service);
int scan_top_ports(const char *ip, char *flag);
void *scan_ports_thread(void *args);
int scan_all_ports(const char *ip);


#endif // PORT_SCANNER_H