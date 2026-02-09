#include "port_scanner.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stdout, "Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }
    const char *target_ip = argv[1];
    scan_top_ports(target_ip);
    return 0;
}