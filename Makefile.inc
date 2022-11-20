SHELL:=/bin/bash
GCC=gcc
GCC_FLAGS=-Wall -pedantic -fsanitize=address -lrt -pthread -std=gnu11 -g


TARGET_CLIENT := ../client5
TARGET_SERVER := ../socks5d