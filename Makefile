CC=gcc
CFLAGS=-std=c11 -Wall -D_DEFAULT_SOURCE
LDFLAGS=-O3
OBJ=$(patsubst %.c, %.o, $(wildcard *.c))
TARGET=gotredirect-dl
.PHONY: all clean
all: $(TARGET)
$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $(TARGET)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJ) $(TARGET)
