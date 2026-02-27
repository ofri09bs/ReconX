#include "port_scanner.h"
#include "dir_buster.h"
#include "utils.h"
#include "ping_sweeper.h"
#include "dns_enum.h"
#include "service_grabber.h"
#include "lan_sniffer.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

// ANSI color codes for better output formatting
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

#define DIR_WORDLIST_PATH "wordlists/common.txt"
#define DNS_WORDLIST_PATH "wordlists/subdomains.txt"


int handle_port_scanner() {

    char target_ip[16] = "";
    char ports[256] = "";
    int thread_count = 15;

    while(1) {
        printf(BOLD CYAN "reconx/port_scanner > " RESET);

        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        if (command == NULL) {
            continue; // No command entered
        }

        if (strcmp(command, "show") == 0) {
            printf(YELLOW "Module Options:\n" RESET);
            printf(" ------------------------------------------------------------\n\n");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "TARGET", "required", "The target IP address to scan");

            printf("  " GREEN "%-12s" RESET YELLOW "%-12s" RESET "%s\n",
            "PORTS", "optional", "The ports to scan (Default: 1-1024)");

            printf("  " GREEN "%-12s" RESET YELLOW "%-12s" RESET "%s\n",
            "THREADS", "optional", "Number of threads to use (Default: 15)");

            printf("\n ------------------------------------------------------------\n");

        }

        else if (strcmp(command, "set") == 0) {
            char* option = strtok(NULL, " ");
            char* value = strtok(NULL, " ");

            if (option == NULL || value == NULL) {
                printf(RED "Usage: set <option> <value>\n" RESET);
                continue;
            }
            // TARGET option validation
            if (strcmp(option, "TARGET") == 0) {

                if (!is_valid_ip(value)) {
                    printf(RED "Invalid IP address format. Please enter a valid IPv4 address.\n" RESET);
                    continue;
                }

                strncpy(target_ip, value, sizeof(target_ip));
                target_ip[sizeof(target_ip) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "TARGET => %s\n" RESET, target_ip);
            }
            // PORTS option validation
            else if (strcmp(option, "PORTS") == 0) {
                strncpy(ports, value, sizeof(ports));
                ports[sizeof(ports) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "PORTS => %s\n" RESET, ports);
            }
            // THREADS option validation
            else if (strcmp(option, "THREADS") == 0) {
                thread_count = atoi(value);
                if (thread_count <= 0) {
                    printf(RED "Invalid thread count. Please enter a positive integer.\n" RESET);
                    continue;
                }
                printf(GREEN "THREADS => %d\n" RESET, thread_count);
            }

            else {
                printf(RED "Unknown option: %s\n" RESET, option);
            }
        }

        else if (strcmp(command, "run") == 0) {
            if (strlen(target_ip) == 0) {
                printf(RED "Please set a valid TARGET IP address before running the port scanner.\n" RESET);
                continue;
            }
            printf(YELLOW "Running port scanner...\n" RESET);
            scan_ports(target_ip, ports, thread_count);
        }

        else if (strcmp(command, "back") == 0) {
            printf(YELLOW "Returning to main menu...\n" RESET);
            break; // Exit the port scanner menu
        }

        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }
    }

    return 0;
}

int handle_dir_buster() {
    char target_ip[16] = "";
    int target_port = 80;
    char wordlist_path[256] = DIR_WORDLIST_PATH;

    while(1) {
        printf(BOLD CYAN "reconx/dir_buster > " RESET);

        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        if (command == NULL) {
            continue; // No command entered
        }

        if (strcmp(command, "show") == 0) {
            printf(YELLOW "Module Options:\n" RESET);
            printf(" ------------------------------------------------------------\n\n");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "TARGET", "required", "The target IP address to scan");

            printf("  " GREEN "%-12s" RESET YELLOW "%-12s" RESET "%s\n",
            "PORT", "optional", "The target port to scan (Default: 80)");

            printf("  " GREEN "%-12s" RESET YELLOW "%-12s" RESET "%s\n",
            "WORDLIST", "optional", "Path to the wordlist file (Default: common.txt)");

            printf("\n ------------------------------------------------------------\n");

        }

        else if (strcmp(command, "set") == 0) {
            char* option = strtok(NULL, " ");
            char* value = strtok(NULL, " ");

            if (option == NULL || value == NULL) {
                printf(RED "Usage: set <option> <value>\n" RESET);
                continue;
            }
            // TARGET option validation
            if (strcmp(option, "TARGET") == 0) {

                if (!is_valid_ip(value)) {
                    printf(RED "Invalid IP address format. Please enter a valid IPv4 address.\n" RESET);
                    continue;
                }

                strncpy(target_ip, value, sizeof(target_ip));
                target_ip[sizeof(target_ip) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "TARGET => %s\n" RESET, target_ip);
            }
            // PORT option validation
            else if (strcmp(option, "PORT") == 0) {
                target_port = atoi(value);
                if (target_port <= 0 || target_port > 65535) {
                    printf(RED "Invalid port number. Please enter a value between 1 and 65535.\n" RESET);
                    continue;
                }
                printf(GREEN "PORT => %d\n" RESET, target_port);
            }
            // WORDLIST option validation
            else if (strcmp(option, "WORDLIST") == 0) {
                strncpy(wordlist_path, value, sizeof(wordlist_path));
                wordlist_path[sizeof(wordlist_path) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "WORDLIST => %s\n" RESET, wordlist_path);
            }

            else {
                printf(RED "Unknown option: %s\n" RESET, option);
            }
        }

        else if (strcmp(command, "run") == 0) {
            if (strlen(target_ip) == 0) {
                printf(RED "Please set a valid TARGET IP address before running the directory buster.\n" RESET);
                continue;
            }
            printf(YELLOW "Running directory buster...\n" RESET);
            start_dir_buster(target_ip, target_port, wordlist_path);
        }

        else if (strcmp(command, "back") == 0) {
            printf(YELLOW "Returning to main menu...\n" RESET);
            break; // Exit the dir buster menu
        }

        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }
    }
    return 0;
}


int handle_ping_sweeper() {
    char target_ip[16] = "";

    while(1) {
        printf(BOLD CYAN "reconx/ping_sweeper > " RESET);

        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        if (command == NULL) {
            continue; // No command entered
        }

        if (strcmp(command, "show") == 0) {
            printf(YELLOW "Module Options:\n" RESET);
            printf(" ------------------------------------------------------------\n\n");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "TARGET", "required", "The target IP address to scan (e.g., 192.168.1.10)\n");
            printf(" ------------------------------------------------------------\n");
        }

        else if (strcmp(command, "set") == 0) {
            char* option = strtok(NULL, " ");
            char* value = strtok(NULL, " ");

            if (option == NULL || value == NULL) {
                printf(RED "Usage: set <option> <value>\n" RESET);
                continue;
            }
            // TARGET option validation
            if (strcmp(option, "TARGET") == 0) {

                if (!is_valid_ip(value)) {
                    printf(RED "Invalid IP address format. Please enter a valid IPv4 address.\n" RESET);
                    continue;
                }

                strncpy(target_ip, value, sizeof(target_ip));
                target_ip[sizeof(target_ip) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "TARGET => %s\n" RESET, target_ip);
            }

            else {
                printf(RED "Unknown option: %s\n" RESET, option);
            }
        }

        else if (strcmp(command, "run") == 0) {
            if (strlen(target_ip) == 0) {
                printf(RED "Please set a valid TARGET IP address before running the ping sweeper.\n" RESET);
                continue;
            }
            printf(YELLOW "Running ping sweeper...\n" RESET);
            ping_sweep(target_ip);
        }

        else if (strcmp(command, "back") == 0) {
            printf(YELLOW "Returning to main menu...\n" RESET);
            break; // Exit the ping sweeper menu
        }

        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }

    }
    return 0;
}


int handle_dns_enum() {
    char target_domain[256] = "";
    char wordlist_path[256] = DNS_WORDLIST_PATH;
    int thread_count = 15;

    while(1) {
        printf(BOLD CYAN "reconx/dns_enum > " RESET);

        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        if (command == NULL) {
            continue; // No command entered
        }

        if (strcmp(command, "show") == 0) {
            printf(YELLOW "Module Options:\n" RESET);
            printf(" ------------------------------------------------------------\n\n");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "DOMAIN", "required", "The target domain to enumerate subdomains for");

            printf("  " GREEN "%-12s" RESET YELLOW "%-12s" RESET "%s\n",
            "WORDLIST", "optional", "Path to the wordlist file (Default: subdomains.txt)");

            printf("  " GREEN "%-12s" RESET YELLOW "%-12s" RESET "%s\n",
            "THREADS", "optional", "Number of threads to use (Default: 15)");

            printf("\n ------------------------------------------------------------\n");

        }

        else if (strcmp(command, "set") == 0) {
            char* option = strtok(NULL, " ");
            char* value = strtok(NULL, " ");

            if (option == NULL || value == NULL) {
                printf(RED "Usage: set <option> <value>\n" RESET);
                continue;
            }
            // DOMAIN option validation
            if (strcmp(option, "DOMAIN") == 0) {
                strncpy(target_domain, value, sizeof(target_domain));
                target_domain[sizeof(target_domain) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "DOMAIN => %s\n" RESET, target_domain);
            }
            // WORDLIST option validation
            else if (strcmp(option, "WORDLIST") == 0) {
                strncpy(wordlist_path, value, sizeof(wordlist_path));
                wordlist_path[sizeof(wordlist_path) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "WORDLIST => %s\n" RESET, wordlist_path);
            }
            // THREADS option validation
            else if (strcmp(option, "THREADS") == 0) {
                thread_count = atoi(value);
                if (thread_count <= 0) {
                    printf(RED "Invalid thread count. Please enter a positive integer.\n" RESET);
                    continue;
                }
                printf(GREEN "THREADS => %d\n" RESET, thread_count);
            }   

            else {
                printf(RED "Unknown option: %s\n" RESET, option);
            }
        }
        
        else if (strcmp(command, "run") == 0) {
            if (strlen(target_domain) == 0) {
                printf(RED "Please set a valid DOMAIN before running the DNS enumerator.\n" RESET);
                continue;
            }
            printf(YELLOW "Running DNS enumerator...\n" RESET);
            dns_enumerate(target_domain, wordlist_path, thread_count);
        }

        else if (strcmp(command, "back") == 0) {
            printf(YELLOW "Returning to main menu...\n" RESET);
            break; // Exit the DNS enumerator menu
        }

        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }
    }
    return 0;
}


int handle_service_grabber() {
    char target_ip[16] = "";
    int target_port = 0;

    while(1) {
        printf(BOLD CYAN "reconx/service_grabber > " RESET);

        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        if (command == NULL) {
            continue; // No command entered
        }

        if (strcmp(command, "show") == 0) {
            printf(YELLOW "Module Options:\n" RESET);
            printf(" ------------------------------------------------------------\n\n");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "TARGET", "required", "The target IP address to grab service info from");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "PORT", "required", "The target port to grab service info from");

            printf("\n ------------------------------------------------------------\n");

        }

        else if (strcmp(command, "set") == 0) {
            char* option = strtok(NULL, " ");
            char* value = strtok(NULL, " ");

            if (option == NULL || value == NULL) {
                printf(RED "Usage: set <option> <value>\n" RESET);
                continue;
            }
            // TARGET option validation
            if (strcmp(option, "TARGET") == 0) {

                if (!is_valid_ip(value)) {
                    printf(RED "Invalid IP address format. Please enter a valid IPv4 address.\n" RESET);
                    continue;
                }

                strncpy(target_ip, value, sizeof(target_ip));
                target_ip[sizeof(target_ip) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "TARGET => %s\n" RESET, target_ip);
            }
            // PORT option validation
            else if (strcmp(option, "PORT") == 0) {
                target_port = atoi(value);
                if (target_port <= 0 || target_port > 65535) {
                    printf(RED "Invalid port number. Please enter a value between 1 and 65535.\n" RESET);
                    continue;
                }
                printf(GREEN "PORT => %d\n" RESET, target_port);
            }
            
            else {
                printf(RED "Unknown option: %s\n" RESET, option);
            }
        }
        
        else if (strcmp(command, "run") == 0) {
            if (strlen(target_ip) == 0) {
                printf(RED "Please set a valid TARGET IP address before running the service grabber.\n" RESET);
                continue;
            }
            if (target_port <= 0 || target_port > 65535) {
                printf(RED "Please set a valid PORT number between 1 and 65535 before running the service grabber.\n" RESET);
                continue;
            }
            printf(YELLOW "Running service grabber...\n" RESET);
            grab_service_info(target_ip, target_port);
        }

        else if (strcmp(command, "back") == 0) {
            printf(YELLOW "Returning to main menu...\n" RESET);
            break; // Exit the service grabber menu
        }

        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }
    }
    return 0;
}

int handle_lan_sniffer() {
    char iface[256] = "";

    while(1) {
        printf(BOLD CYAN "reconx/lan_sniffer > " RESET);

        //check if program is run with root privileges
        if (geteuid() != 0) {
            printf(RED "Error: LAN sniffer requires root privileges to run.\n" RESET);
            printf(RED "Please run the program as root or with sudo.\n" RESET);
            return -1;
        }

        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        if (command == NULL) {
            continue; // No command entered
        }

        if (strcmp(command, "show") == 0) {
            printf(YELLOW "Module Options:\n" RESET);
            printf(" ------------------------------------------------------------\n\n");

            printf("  " GREEN "%-12s" RESET RED "%-12s" RESET "%s\n",
            "IFACE", "required", "The network interface to sniff on (you can find this using 'ip addr' command)");

            printf("\n ------------------------------------------------------------\n");

        }

        else if (strcmp(command, "set") == 0) {
            char* option = strtok(NULL, " ");
            char* value = strtok(NULL, " ");

            if (option == NULL || value == NULL) {
                printf(RED "Usage: set <option> <value>\n" RESET);
                continue;
            }
            // IFACE option validation
            if (strcmp(option, "IFACE") == 0) {
                strncpy(iface, value, sizeof(iface));
                iface[sizeof(iface) - 1] = '\0'; // Ensure null-termination
                printf(GREEN "IFACE => %s\n" RESET, iface);
            }

            else {
                printf(RED "Unknown option: %s\n" RESET, option);
            }
        }

        else if (strcmp(command, "run") == 0) {
            if (strlen(iface) == 0) {
                printf(RED "Please set a valid IFACE before running the LAN sniffer.\n" RESET);
                continue;
            }
            printf(YELLOW "Running LAN sniffer...\n" RESET);
            start_lan_sniffer(iface);
        }

        else if (strcmp(command, "back") == 0) {
            printf(YELLOW "Returning to main menu...\n" RESET);
            break; // Exit the LAN sniffer menu
        }
        
        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; // Unused parameter
    (void)argv; // Unused parameter
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

    printf(BOLD GREEN "        ReconX Network Scanner v2.3\n" RESET);
    printf(YELLOW "        Author: ofribs\n\n" RESET);

    printf(BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" RESET);

    // new CLI parsing logic
    while(1) {
        printf(BOLD CYAN "reconx > " RESET);
        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break; // Exit on EOF (Ctrl+D)
        }

        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        char* tool = strtok(NULL, " ");

        if (command == NULL) {
            continue; // No command entered
        }

        if (tool == NULL && strcmp(command, "use") == 0) {
            printf(RED "Usage: use <tool>\n" RESET);
            continue;
        }

        if (strcmp(command, "help") == 0) {
            printf("\n");
            printf(BOLD CYAN "ReconX Framework Help\n" RESET);
            printf(BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" RESET);

            /* Core Commands */
            printf(YELLOW "Core Commands:\n" RESET);
            printf("  " GREEN "%-18s" RESET "%s\n", "help", "Show this help menu");
            printf("  " GREEN "%-18s" RESET "%s\n", "use <module>", "Select a module");
            printf("  " GREEN "%-18s" RESET "%s\n", "exit", "Exit ReconX");
            printf("\n");

            /* Available Modules */
            printf(YELLOW "Available Modules:\n" RESET);
            printf("  " GREEN "%-18s" RESET "%s\n", "port_scanner", "Scan for open TCP ports");
            printf("  " GREEN "%-18s" RESET "%s\n", "dir_buster", "Directory brute-forcing on web servers");
            printf("  " GREEN "%-18s" RESET "%s\n", "ping_sweeper", "Discover active hosts via ICMP");
            printf("  " GREEN "%-18s" RESET "%s\n", "dns_enum", "Enumerate subdomains using a wordlist");
            printf("  " GREEN "%-18s" RESET "%s\n", "service_grabber", "Grab service information from open ports");
            printf("\n");

            /* Basic Workflow */
            printf(YELLOW "Basic Workflow:\n" RESET);
            printf("  " CYAN "1." RESET " use <module>\n");
            printf("  " CYAN "2." RESET " show\n");
            printf("  " CYAN "3." RESET " set <OPTION> <VALUE>\n");
            printf("  " CYAN "4." RESET " run\n");
            printf("  " CYAN "5." RESET " back\n");
            printf("\n");
            
            continue;
        }

        if (strcmp(command, "exit") == 0) {
            printf(YELLOW "Exiting ReconX. Goodbye!\n" RESET);
            break;
        }

        if (strcmp(command, "use") == 0) {
            
            if (strcmp(tool, "port_scanner") == 0) {
                handle_port_scanner();
            }
            else if (strcmp(tool, "dir_buster") == 0) {
                handle_dir_buster();
            }
            else if (strcmp(tool, "ping_sweeper") == 0) {
                handle_ping_sweeper();
            }
             else if (strcmp(tool, "dns_enum") == 0) {
                handle_dns_enum();
            }
             else if (strcmp(tool, "service_grabber") == 0) {
                handle_service_grabber();
            }
            else if (strcmp(tool, "lan_sniffer") == 0) {
                handle_lan_sniffer();
            }
             else {
                printf(RED "Unknown tool: %s\n" RESET, tool);
            }
        }
        else {
            printf(RED "Unknown command: %s\n" RESET, command);
        }
    }

    return 0;
}

