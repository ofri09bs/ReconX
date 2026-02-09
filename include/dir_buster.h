#ifndef DIR_BUSTER_H
#define DIR_BUSTER_H

int start_dir_buster(const char *ip, int port, const char *wordlist_path);
int send_http_request(int sock, const char *path ,char *ip);

#endif // DIR_BUSTER_H