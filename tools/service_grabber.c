#include "service_grabber.h"
#include "utils.h"
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

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"


// ##### Speaking service checks (They send data without any request) ######

int check_ssh(char* response_banner) {

    if (strstr(response_banner, "SSH") != NULL) {
        response_banner[strcspn(response_banner, "\r\n")] = '\0'; // Remove trailing newline
        return SERVICE_SSH; // SSH detected
    }
    return SERVICE_UNKNOWN; // Not SSH
}

int check_ftp(char* response_banner) {
    if (strstr(response_banner, "FTP") != NULL) {
        response_banner[strcspn(response_banner, "\r\n")] = '\0'; // Remove trailing newline
        return SERVICE_FTP; // FTP detected
    }
    return SERVICE_UNKNOWN; // Not FTP
}

int check_smtp(char* response_banner) {
    if (strstr(response_banner, "SMTP") != NULL) {
        response_banner[strcspn(response_banner, "\r\n")] = '\0'; // Remove trailing newline
        return SERVICE_SMTP; // SMTP detected
    }
    return SERVICE_UNKNOWN; // Not SMTP
}

int check_pop3(char* response_banner) {
    if (strstr(response_banner, "POP3") != NULL || strstr(response_banner, "+OK") != NULL) {
        response_banner[strcspn(response_banner, "\r\n")] = '\0'; // Remove trailing newline
        return SERVICE_POP3; // POP3 detected
    }
    return SERVICE_UNKNOWN; // Not POP3
}

int check_imap(char* response_banner) {
    if (strstr(response_banner, "IMAP") != NULL || strstr(response_banner, "* OK") != NULL) {
        response_banner[strcspn(response_banner, "\r\n")] = '\0'; // Remove trailing newline
        return SERVICE_IMAP; // IMAP detected
    }
    return SERVICE_UNKNOWN; // Not IMAP
}

int check_telnet(char* response_banner) {
    char* hex_login = "\xff\xfb\x01"; // IAC WILL ECHO
    if (strstr(response_banner, "login") != NULL || strstr(response_banner, hex_login) != NULL) {
        response_banner[strcspn(response_banner, "\r\n")] = '\0'; // Remove trailing newline
        return SERVICE_TELNET; // Telnet detected
    }
    return SERVICE_UNKNOWN; // Not Telnet
}


int check_mysql(char* response_banner) {
    char* hex_mysql = "\x00\x00\x00\x0a"; // MySQL protocol version 10
    if (memcmp(response_banner, hex_mysql, 4) == 0 || strstr(response_banner, "MySQL") != NULL) {
        char* version = response_banner + strcspn(response_banner, hex_mysql) + 4; // Skip the hex_mysql bytes and get version string
        version[strcspn(version, "\r\n")] = '\0'; // Remove trailing newline
        strncpy(response_banner, version, 256); // Copy version string back to response_banner
        return SERVICE_MYSQL; // MySQL detected
    }
    return SERVICE_UNKNOWN; // Not MySQL
}

int check_vnc(char* response_banner) {
    if (strstr(response_banner, "RFB") != NULL) {
        response_banner[strcspn(response_banner, "\n")] = '\0'; // Remove trailing newline
        return SERVICE_VNC; // VNC detected
    }
    return SERVICE_UNKNOWN; // Not VNC
}


int check_speaking_services(char* response_banner) {
    int service_type = SERVICE_UNKNOWN;

    if ((service_type = check_ssh(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_ftp(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_smtp(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_pop3(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_imap(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_telnet(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_mysql(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_vnc(response_banner)) != SERVICE_UNKNOWN) {
        return service_type;
    }

    return SERVICE_UNKNOWN; // No known speaking service detected
}


// ##### Quite service checks (They don't send data until a request is made) ######

int check_http(int port, const char* ip, char* buffer) {
    // Send a simple HTTP request to check for HTTP service
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const char* http_request = "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    send(sock, http_request, strlen(http_request), 0);

    // Try to receive a response
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        if (strstr(buffer, "HTTP/") != NULL) {
            if (strstr(buffer, "Server:") != NULL) {
                char* server_header = strstr(buffer, "Server:") + 7; // Skip "Server: "
                server_header[strcspn(server_header, "\r\n")] = '\0'; // Remove trailing newline
                strncpy(buffer, server_header, 255); // Copy server info back to buffer
                buffer[255] = '\0'; // Ensure null termination
            }
            else {
                buffer[0] = '\0'; // Clear buffer if no server info is found
            }
            close(sock);
            return SERVICE_HTTP; // HTTP detected
        }
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not HTTP or no response received
}


int check_https(int port, const char* ip, char* buffer) {
    // try to start TLS handshake by sending ClientHello
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const unsigned char client_hello[] = {
    // --- TLS Record Layer ---
    0x16,                   // Content Type: Handshake (22)
    0x03, 0x01,             // Version: TLS 1.0 (Used for initial connection compatibility)
    0x00, 0x2f,             // Length: 47 bytes following

    // --- Handshake Protocol ---
    0x01,                   // Handshake Type: Client Hello (1)
    0x00, 0x00, 0x2b,       // Length of the Handshake payload: 43 bytes
    0x03, 0x03,             // Version: TLS 1.2

    // Random Data (32 bytes) - Typically 4 bytes Unix time + 28 random bytes
    // Filled with dummy data for this structural example
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,

    0x00,                   // Session ID Length: 0 (No previous session to resume)
    0x00, 0x02,             // Cipher Suites Length: 2 bytes
    0x00, 0x2f,             // Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
    0x01,                   // Compression Methods Length: 1 byte
    0x00,                   // Compression Method: Null (0)
    0x00, 0x00              // Extensions Length: 0 (No extensions included)
    };
    send(sock, client_hello, sizeof(client_hello), 0);
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0 && (memcmp(buffer, "\x16\x03", 2) == 0 || memcmp(buffer, "\x15\x03", 2) == 0)) {
        close(sock);
        return SERVICE_HTTPS; // HTTPS detected (Server responded to TLS ClientHello)
        // completing the TLS handshake and extracting server info would require a full TLS implementation, which is beyond the scope of this simple service grabber
    }

    close(sock);
    return SERVICE_UNKNOWN; // Not HTTPS or no response received               
}

int check_redis(int port, const char* ip, char* buffer) {
    // Send a simple Redis PING command
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const char* redis_ping = "*1\r\n$4\r\nPING\r\n";
    send(sock, redis_ping, strlen(redis_ping), 0);

    // Try to receive a response
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        if (strstr(buffer, "+PONG") != NULL) {
            close(sock);
            return SERVICE_REDIS; // Redis detected
        }
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not Redis or no response received
}

int check_memcached(int port, const char* ip, char* buffer) {
    // Send a simple Memcached version command
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const char* memcached_version = "version\r\n";
    send(sock, memcached_version, strlen(memcached_version), 0);

    // Try to receive a response
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        if (strstr(buffer, "VERSION") != NULL) {
            char* version_info = strstr(buffer, "VERSION") + 8; // Skip "VERSION "
            version_info[strcspn(version_info, "\r\n")] = '\0'; // Remove trailing newline
            strncpy(buffer, version_info, 255); // Copy version info back to buffer
            buffer[255] = '\0'; // Ensure null termination
            close(sock);
            return SERVICE_MEMCACHED; // Memcached detected
        }
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not Memcached or no response received
}

int check_rdp(int port, const char* ip, char* buffer) {
    // Send a simple RDP negotiation request
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const unsigned char rdp_request[] = {
        0x03, 0x00, 0x00, 0x0b, // TPKT Header: Version 3, Reserved 0, Length 11
        0x06,                   // X.224 Data: Length of remaining data (6 bytes)
        0xe0,                   // X.224 Data: Type (EOT)
        0x00,                   // X.224 Data: Flags
        0x00,                   // X.224 Data: Connection ID (High byte)
        0x00                    // X.224 Data: Connection ID (Low byte)
    };
    send(sock, rdp_request, sizeof(rdp_request), 0);
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0 && memcmp(buffer, "\x03\x00", 2) == 0) {
        close(sock);
        return SERVICE_RDP; // RDP detected (Server responded to RDP negotiation request)
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not RDP or no response received
}

int check_smb(int port, const char* ip, char* buffer) {
    // Send a simple SMB negotiation request
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const unsigned char smb_request[] = {
        0x00, 0x00, 0x00, 0x85, // NetBIOS Session Service Header: Length 133 bytes
        0xff, 0x53, 0x4d, 0x42, // SMB Header: Protocol ID "SMB"
        0x72,                   // SMB Header: Command (Negotiate Protocol)
        0x00,                   // SMB Header: Status
        0x00,                   // SMB Header: Flags
        0x18,                   // SMB Header: Flags2
        0x01, 0x28,             // SMB Header: PID High
        0x00, 0x00,             // SMB Header: Signature (8 bytes)
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,                   // SMB Header: Reserved
        0x00,                   // SMB Header: Tree ID
        0x2f,                   // SMB Header: Process ID
        0x4b,                   // SMB Header: User ID
        0xc5                    // SMB Header: Multiplex ID
    };
    send(sock, smb_request, sizeof(smb_request), 0);
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0 && memcmp(buffer + 4, "SMB", 3) == 0) {
        close(sock);
        return SERVICE_SMB; // SMB detected (Server responded to SMB negotiation request)
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not SMB or no response received
}

int check_postgresql(int port, const char* ip, char* buffer) {
    // Send a simple PostgreSQL startup message
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const unsigned char pgsql_startup[] = {
        0x00, 0x00, 0x00, 0x08, // Length of the message (8 bytes)
        0x00, 0x03, 0x00, 0x00  // Protocol version 3.0
    };
    send(sock, pgsql_startup, sizeof(pgsql_startup), 0);
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0 && memcmp(buffer, "R", 1) == 0) {
        close(sock);
        return SERVICE_POSTGRESQL; // PostgreSQL detected (Server responded to startup message)
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not PostgreSQL or no response received
}

int check_mongodb(int port, const char* ip, char* buffer) {
    // Send a simple MongoDB isMaster command
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const unsigned char mongodb_isMaster[] = {
        0x3a, 0x00, 0x00, 0x00, // Message Length (58 bytes)
        0x00, 0x00, 0x00, 0x00, // Request ID
        0xff, 0xff, 0xff, 0xff, // Response To
        0xd4, 0x07, 0x00, 0x00, // OpCode: OP_QUERY (2004)
        // Query for "admin.$cmd" collection with isMaster command
        0x00,                   // Flags
        0x00,                   // Full Collection Name (null-terminated)
        'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', '\0',
        0x00,                   // Number to skip
        0x01,                   // Number to return
        // BSON document for { isMaster: 1 }
        0x16, 0x00, 0x00, 0x00, // Document length (22 bytes)
        0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', '\0', // isMaster: int32
        0x01, 0x00, 0x00, 0x00,
        0x00                    // End of document
    };
    send(sock, mongodb_isMaster, sizeof(mongodb_isMaster), 0);
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0 && memcmp(buffer + 12, "\xd4\x07", 2) == 0) {
        close(sock);
        return SERVICE_MONGODB; // MongoDB detected (Server responded to isMaster command)
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not MongoDB or no response received
}

int check_ldap(int port, const char* ip, char* buffer) {
    // Send a simple LDAP bind request
    int sock = open_socket(ip, port);
    if (sock < 0) {
        return SERVICE_UNKNOWN; // Unable to connect
    }
    const unsigned char ldap_bind[] = {
        0x30, 0x1b,             // LDAPMessage: SEQUENCE of length 27 bytes
        0x02, 0x01, 0x01,       // messageID: INTEGER (1)
        0x60, 0x16,             // bindRequest: [APPLICATION 0] SEQUENCE of length 22 bytes
        0x02, 0x01, 0x03,       // version: INTEGER (3)
        0x04, 0x00              // name: OCTET STRING (empty)
    };
    send(sock, ldap_bind, sizeof(ldap_bind), 0);
    ssize_t bytes_received = recv(sock, buffer, 1023, 0);
    if (bytes_received > 0 && memcmp(buffer + 2, "\x61\x16", 2) == 0) {
        close(sock);
        return SERVICE_LDAP; // LDAP detected (Server responded to bind request)
    }
    close(sock);
    return SERVICE_UNKNOWN; // Not LDAP or no response received
}



int check_quite_services(int port, const char* ip, char* buffer) {
    int service_type = SERVICE_UNKNOWN;

    if ((service_type = check_http(port, ip, buffer)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_https(port, ip, buffer)) != SERVICE_UNKNOWN) {
        memset(buffer, 0, 1024); // Clear buffer (no printable response expected from HTTPS handshake)
        return service_type;
    }
    if ((service_type = check_redis(port, ip, buffer)) != SERVICE_UNKNOWN) {
        memset(buffer, 0, 1024); // Clear buffer (no printable response expected from Redis PING)
        return service_type;
    }
    if ((service_type = check_memcached(port, ip, buffer)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_rdp(port, ip, buffer)) != SERVICE_UNKNOWN) {
        memset(buffer, 0, 1024); // Clear buffer (no printable response expected from RDP negotiation)
        return service_type;
    }
    if ((service_type = check_smb(port, ip, buffer)) != SERVICE_UNKNOWN) {
        memset(buffer, 0, 1024); // Clear buffer (no printable response expected from SMB negotiation)
        return service_type;
    }
    if ((service_type = check_postgresql(port, ip, buffer)) != SERVICE_UNKNOWN) {
        memset(buffer, 0, 1024); // Clear buffer (no printable response expected from PostgreSQL startup)
        return service_type;
    }
    if ((service_type = check_mongodb(port, ip, buffer)) != SERVICE_UNKNOWN) {
        return service_type;
    }
    if ((service_type = check_ldap(port, ip, buffer)) != SERVICE_UNKNOWN) {
        memset(buffer, 0, 1024); // Clear buffer (no printable response expected from LDAP bind)
        return service_type;
    }

    return SERVICE_UNKNOWN; // No known quite service detected
}



int grab_service_info(const char* ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    ssize_t bytes_received;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    // Set a timeout for receiving data
    struct timeval timeout;
    timeout.tv_sec = 3; // 5 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int service_type = SERVICE_UNKNOWN;
    bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer

        if ((service_type = check_speaking_services(buffer)) != SERVICE_UNKNOWN) {
            char* service_name = get_service_name(service_type);
            printf("Service on %s:%d => " GREEN "%s" RESET YELLOW " (%s)\n" RESET, ip, port, service_name, buffer);
        }
        else {
            printf("Service on %s:%d =>" YELLOW " Unknown Service\n" RESET, ip, port);
        }
    }
    else if (bytes_received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        service_type = check_quite_services(port, ip, buffer);
        char* service_name = get_service_name(service_type);
        if (service_type != SERVICE_UNKNOWN) {
            if (strlen(buffer) > 0) {
                printf("Service on %s:%d => " GREEN "%s" RESET YELLOW " (%s)\n" RESET, ip, port, service_name, buffer);
            }
            else {
                printf("Service on %s:%d => " GREEN "%s" RESET "\n", ip, port, service_name);
            }
        }
        else {
            printf("Service on %s:%d =>" YELLOW " Unknown Service\n" RESET, ip, port);
        }
    }
    else {
        printf(RED "Service on %s:%d => No response or error\n" RESET, ip, port);
    }

    close(sockfd);
    return 0;
}