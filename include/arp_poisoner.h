#ifndef ARP_POISONER_H
#define ARP_POISONER_H

int start_arp_poisoner(char* iface, char* target_ip);
int start_packet_sniffer(char* target_ip);
int get_default_gateway(char *gateway_ip);
int get_mac_from_ip(const char *ip, char *mac_buffer);
void* spoofing_thread(void* args);
void start_arp_spoofing(char* iface, char* target_ip, char* target_mac_str, char* router_ip, char* router_mac_str);
void send_arp_reply(int sockdf, int ifindex, unsigned char* attacker_mac, unsigned char* target_mac, char* target_ip, char* spoofed_ip);


#endif // ARP_POISONER_H

