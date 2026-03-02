#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <string.h>

int starts_with(char *str, const char *prefix);
int get_file_line_count(const char *file_path);
unsigned short calculate_checksum(void *b, int len);
int is_valid_ip(const char *ip);
int open_socket(const char* ip, int port);
char* get_service_name(int service_type);
void parse_mac(const char* mac_str, unsigned char* mac_bytes);

#endif // UTILS_H