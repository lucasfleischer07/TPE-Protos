SHELL:=/bin/bash
GCC=gcc
GCC_FLAGS=-Wall -fsanitize=address -pthread
GCC_DEBUG_FLAGS=-g

TARGET_CLIENT := ../client
TARGET_SERVER := ../socks5d