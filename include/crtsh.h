#ifndef CRTSH_H
#define CRTSH_H

#include <curl/curl.h>
#include <stdio.h>

typedef struct {
    char* data;
    size_t size;
} Memory;

int start_crtsh_enumeration(const char *domain);
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
int parse_response(const char *response,const char* domain);
void reset_subdomains();
int is_duplicate(const char *subdomain);
int send_https_request(const char *url, Memory *response);

#endif // CRTSH_H