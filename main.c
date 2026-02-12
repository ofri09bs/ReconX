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

// ANSI color codes for better output formatting
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    printf("\n");
    printf(BOLD CYAN);
    printf("██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗\n");
    printf("██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝\n");
    printf("██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ \n");
    printf("██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ \n");
    printf("██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗\n");
    printf("╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝\n");
    printf(RESET);

    printf(BOLD GREEN "        ReconX Network Scanner v1.0\n" RESET);
    printf(YELLOW "        Author: ofribs\n\n" RESET);

    printf(BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" RESET);
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {

    printf(BOLD "Usage:\n" RESET);
    printf("  %s <target_ip> [options]\n\n", argv[0]);

    printf(BOLD "Options:\n" RESET);
    printf("  " GREEN "-p" RESET "        Run Port Scanner\n");
    printf("  " GREEN "-d" RESET "        Run Directory Buster\n");
    printf("  " GREEN "-a" RESET "        Scan all ports (1-65535)\n");
    printf("              Default: Top 1024 ports\n\n");

    printf(BOLD "Examples:\n" RESET);
    printf("  %s 192.168.1.10 -p\n", argv[0]);
    printf("  %s 10.0.0.5 -p -a\n", argv[0]);
    printf("  %s 192.168.1.10 -d\n\n", argv[0]);

    printf(BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" RESET);

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
        else if (strcmp(argv[i], "-a") == 0) {
            printf("Scanning all ports (1-65535)...\n");
            scan_top_ports(target_ip, "-a");
        }
         else {
            printf(RED "Unknown option: %s\n" RESET, argv[i]);
            printf("Use " GREEN "-h" RESET " or " GREEN "--help" RESET " for usage information.\n");
            return 1;
        }
    }
    return 0;
}