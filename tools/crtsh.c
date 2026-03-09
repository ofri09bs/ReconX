#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include "crtsh.h"
#include "utils.h"
#include "db_manager.h"

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

char **found_subdomains = NULL;
int found_count = 0;


int send_https_request(const char *url, Memory *response) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);  // Set the URL for the request
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback); // Set the callback function 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response); // Set the user data for the callback
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "crtsh-client/1.0"); // Set a user agent

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_cleanup(curl);
    return 0;
}

int is_duplicate(const char *subdomain) {
    for (int i = 0; i < found_count; i++) {
        if (strcmp(found_subdomains[i], subdomain) == 0) {
            return 1; // Duplicate found
        }
    }
    return 0; // No duplicate
}

void reset_subdomains() {
    for (int i = 0; i < found_count; i++) {
        free(found_subdomains[i]);
    }
    free(found_subdomains);
    found_subdomains = NULL;
    found_count = 0;
}

int parse_response(const char *response,const char* domain) {
    const char *token = response;
    char timestamp[20];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    int scan_id = create_new_scan(domain, "crt.sh Enumeration", timestamp);
    while ((token = strstr(token, "\"name_value\":\"")) != NULL) {
        token += strlen("\"name_value\":\"");
        const char *end = strchr(token, '"');     
        if (end) {
            size_t len = end - token;
            char *raw_domain = malloc(len + 1);
            strncpy(raw_domain, token, len);
            raw_domain[len] = '\0';
            
            char *p = raw_domain;
            while ((p = strstr(p, "\\n")) != NULL) {
                p[0] = ' ';
                p[1] = ' '; 
            }
            
            char *saveptr;
            char *next_domain = strtok_r(raw_domain, " ", &saveptr);
            
            while (next_domain) {
                char *clean_line = next_domain;
                if (clean_line[0] == '*' && clean_line[1] == '.') {
                    clean_line += 2; 
                }
                
                if (!is_duplicate(clean_line)) {
                    found_subdomains = realloc(found_subdomains, (found_count + 1) * sizeof(char *));
                    found_subdomains[found_count] = strdup(clean_line);
                    printf(GREEN "[+] Found: %s" RESET "\n", clean_line);
                    save_scan_result(scan_id, clean_line, "crt.sh Enumeration");
                    found_count++;
                }
                
                next_domain = strtok_r(NULL, " ", &saveptr); 
            }
            
            free(raw_domain);
            token = end + 1;
        }
    }
    return 0;
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    Memory *mem = (Memory *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

int start_crtsh_enumeration(const char *domain) {

    char url[512];
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%25.%s&output=json", domain);

    Memory response = {0};
    if (send_https_request(url, &response) == 0) {
        int result = parse_response(response.data, domain);
        printf(YELLOW "[*] Found %d unique subdomains." RESET "\n", found_count);
        free(response.data);
        return result;
    }
    return -1;
}