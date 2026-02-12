#ifndef DIR_BUSTER_H
#define DIR_BUSTER_H

int start_dir_buster(const char *ip, int port, const char *wordlist_path);
int send_http_request(int sock, const char *path ,const char *ip);
void *dirbuster_thread(void *args);

#endif // DIR_BUSTER_H