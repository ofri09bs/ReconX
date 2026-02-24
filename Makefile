CC=gcc
CFLAGS=-Wall -Wextra -pedantic -Wno-format-truncation
INC=-Iinclude

SRC= tools/port_scanner.c \
	 tools/utils.c \
	 tools/dir_buster.c \
	 tools/ping_sweeper.c \
	 main.c
OUT=reconx

all:
	$(CC) $(CFLAGS) $(SRC) $(INC) -o $(OUT)