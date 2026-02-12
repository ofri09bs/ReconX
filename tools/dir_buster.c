#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include "utils.h"
#include "dir_buster.h"

#define MAX_WORDS 10000
#define NUM_THREADS 20  // Number of concurrent threads

// Shared resources
char *words[MAX_WORDS];
int word_count = 0;
int current_index = 0;
pthread_mutex_t index_mutex;

// Target configuration (Global so threads can access them)
char target_ip[100];
int target_port;

int send_http_request(int sock, const char *path ,const char *ip) {
    char request[2048];
    char *http_request = "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
    snprintf(request, sizeof(request), http_request, path, ip);
    //printf("Testing: %s\n", path);
    int bytes_sent = send(sock, request, strlen(request), 0);
    if (bytes_sent < 0) {
        return -1;
    }
    
    char buffer[2048];
    int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        return -1;
    }

    buffer[bytes_received] = '\0';
    if (starts_with(buffer, "HTTP/1.1 2")) {  // Check for 2xx status codes
        return 0;
    }
    return -1;
}

void *dirbuster_thread(void *args) {
    (void)args; // Unused parameter
    while(1) {
        char *word_to_test = NULL;

        // Critical Section: Get the next word safely
        pthread_mutex_lock(&index_mutex);
        if (current_index < word_count) {
            word_to_test = words[current_index];
            current_index++;
        }
        pthread_mutex_unlock(&index_mutex);

        // If no more words are left, exit the thread
        if (word_to_test == NULL) {
            break; 
        }

        // Network logic (Socket creation, Connection, Request)        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_port); // Use global port
        inet_pton(AF_INET, target_ip, &addr.sin_addr); // Use global IP

        // Set timeouts
        struct timeval timeout;
        timeout.tv_sec = 1; // Increased slightly for stability
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
             // Send Request
            if (send_http_request(sock, word_to_test, target_ip) == 0) {
                printf("[+] %s:%d/\033[32m%s\033[0m - Found\n", target_ip, target_port, word_to_test);
            }
        }
        
        close(sock);
    }
    return NULL;
}

int start_dir_buster(const char *ip, int port, const char *wordlist_path) {
    // 1. Initialize Globals
    strncpy(target_ip, ip, sizeof(target_ip));
    target_port = port;
    current_index = 0;
    word_count = 0;
    
    pthread_mutex_init(&index_mutex, NULL);

    // 2. Load Wordlist into Memory
    FILE *file = fopen(wordlist_path, "r");
    if (file == NULL) {
        perror("Error opening wordlist");
        return -1;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file) != NULL && word_count < MAX_WORDS) {
        buffer[strcspn(buffer, "\r\n")] = '\0'; // Remove newline
        if (strlen(buffer) > 0) {
            words[word_count] = strdup(buffer); // Allocate memory for the word
            word_count++;
        }
    }
    fclose(file);
    printf("Loaded %d words. Starting %d threads...\n", word_count, NUM_THREADS);

    // 3. Create Thread Pool
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, dirbuster_thread, NULL) != 0) {
            perror("Failed to create thread");
        }
    }

    // 4. Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // 5. Cleanup
    pthread_mutex_destroy(&index_mutex);
    
    // Optional: Free allocated memory for words
    for (int i = 0; i < word_count; i++) {
        free(words[i]);
    }

    return 0;
}