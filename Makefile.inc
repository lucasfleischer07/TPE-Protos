SHELL:=/bin/bash
GCC=gcc
GCC_FLAGS=-Wall -pedantic -fsanitize=address -lrt -pthread -std=gnu11 -g


TARGET_CLIENT := ../client
TARGET_SERVER := ../socks5d