CC=gcc
CFLAGS=-Wall -Wextra -pedantic -Wno-format-truncation
LDFLAGS=-lcurl
INC=-Iinclude

SRC= tools/port_scanner.c \
	 tools/utils.c \
	 tools/dir_buster.c \
	 tools/ping_sweeper.c \
	 tools/dns_enum.c \
	 tools/service_grabber.c \
	 tools/lan_sniffer.c \
	 tools/arp_poisoner.c \
	 tools/crtsh.c \
	 main.c
OUT=reconx

all:
	$(CC) $(CFLAGS) $(SRC) $(INC) -o $(OUT) $(LDFLAGS)