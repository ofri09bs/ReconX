#include "port_scanner.h"
#include "dir_buster.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    printf("ReconX Scanner\n");
    printf("====================\n\n");
    printf("Usage: %s <target_ip> [tools] [-a]\n", argv[0]);

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        fprintf(stdout, "Usage: %s <target_ip> [-a]\n", argv[0]);
        fprintf(stdout, "       -a : Scan all ports (1-65535)\n");
        fprintf(stdout, "       (default: Scan top 1024 ports)\n");
        fprintf(stdout, "       tools : Choose tools to use:\n");
        fprintf(stdout, "                -p : Port Scanner\n");
        fprintf(stdout, "                -d : Directory Buster\n");
        return 0;
    }

    const char *target_ip = argv[1];
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            printf("Starting Port Scanner...\n");
            scan_top_ports(target_ip, NULL);
        }
        else if (strcmp(argv[i], "-d") == 0) {
            printf("Starting Directory Buster...\n");
            start_dir_buster(target_ip, 80, "common.txt");
        }
    }
    return 0;
}