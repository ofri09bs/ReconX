#ifndef LAN_SNIFFER_H
#define LAN_SNIFFER_H

void start_lan_sniffer(const char* iface);
void set_promiscuous_mode(int sockfd, const char* iface);
void register_and_print_host(char* ip_str, char* mac_str, int ttl);
int is_local_ip(uint32_t ip);

#endif // LAN_SNIFFER_H