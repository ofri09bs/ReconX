CC=gcc
CFLAGS=-Wall -Wextra -pedantic
INC=-Iinclude

SRC= tools/port_scanner.c \
	 tools/utils.c \
	 main.c
OUT=build/reconx

all:
	$(CC) $(CFLAGS) $(SRC) $(INC) -o $(OUT)