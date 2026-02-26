#ifndef SERVICE_GRABBER_H
#define SERVICE_GRABBER_H
#include <stdio.h>

typedef enum {
    SERVICE_UNKNOWN,
    SERVICE_SSH,
    SERVICE_FTP,
    SERVICE_SMTP,
    SERVICE_POP3,
    SERVICE_IMAP,
    SERVICE_TELNET,
    SERVICE_MYSQL,
    SERVICE_VNC,
    SERVICE_HTTP,
    SERVICE_HTTPS,
    SERVICE_REDIS,
    SERVICE_MEMCACHED,
    SERVICE_RDP,
    SERVICE_SMB,
    SERVICE_POSTGRESQL,
    SERVICE_MONGODB,
    SERVICE_LDAP
} ServiceType;

int grab_service_info(const char* ip, int port);
int check_quite_services(int port, const char* ip, char* buffer);
int check_speaking_services(char* response_banner);
int check_ldap(int port, const char* ip, char* buffer);
int check_mongodb(int port, const char* ip, char* buffer);
int check_postgresql(int port, const char* ip, char* buffer);
int check_smb(int port, const char* ip, char* buffer);
int check_rdp(int port, const char* ip, char* buffer);
int check_memcached(int port, const char* ip, char* buffer);
int check_redis(int port, const char* ip, char* buffer);
int check_https(int port, const char* ip, char* buffer);
int check_http(int port, const char* ip, char* buffer);
int check_vnc(char* response_banner);
int check_mysql(char* response_banner);
int check_telnet(char* response_banner);
int check_imap(char* response_banner);
int check_pop3(char* response_banner);
int check_smtp(char* response_banner);
int check_ftp(char* response_banner);
int check_ssh(char* response_banner);


#endif // SERVICE_GRABBER_H