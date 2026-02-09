#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

char* scan_port(const char *ip, int port);
int scan_top_ports(const char *ip, char *flag);

#endif // PORT_SCANNER_H