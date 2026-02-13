#include "port_scanner.h"
#include "dir_buster.h"
#include "utils.h"
#include "ping_sweeper.h"
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

#define FLAGS "-p -d -s -pa -h"

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
    printf("  " GREEN "-pa" RESET "        Scan all ports (1-65535)\n");
    printf("              Default: Top 1024 ports\n\n");
    printf("  " GREEN "-s" RESET "        Run Ping Sweep (scan .1 to .254)\n");
    printf("              Needs Sudo Privileges\n\n");
    printf("  " GREEN "-h, --help" RESET "  Show this help message\n\n");

    printf(BOLD "Examples:\n" RESET);
    printf("  %s 192.168.1.10 -p\n", argv[0]);
    printf("  %s 10.0.0.5 -p -pa\n", argv[0]);
    printf("  %s 192.168.1.10 -d\n\n", argv[0]);

    printf(BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" RESET);

    return 0;
    }

    const char *target_ip = argv[1];
    if (target_ip == NULL) {
        fprintf(stderr, RED "[-] Target IP is required\n" RESET);
        return 1;
    }

    int i;

    for (i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            printf(BOLD YELLOW "\n[INFO] Running Port Scanner...\n" RESET);
            scan_top_ports(target_ip, NULL);
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            printf(BOLD YELLOW "\n[INFO] Running Directory Buster...\n" RESET);
            start_dir_buster(target_ip, 80, "common.txt");
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            printf(BOLD YELLOW "\n[INFO] Running Ping Sweep...\n" RESET);
            ping_sweep(target_ip);
        }
        else if (strcmp(argv[i], "-pa") == 0)
        {
            printf(BOLD YELLOW "\n[INFO] Scanning all ports (1-65535)...\n" RESET);
            scan_all_ports(target_ip);
        }
        else {
            printf(RED "[-] Unknown flag: %s\n" RESET, argv[i]);
        }
    }
     
    return 0;
}
