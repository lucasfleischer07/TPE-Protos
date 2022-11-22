SHELL:=/bin/bash
GCC=gcc
GCC_FLAGS=-pthread -g -Wall -Wextra -pedantic -pedantic-errors -O3 -std=c11 -D_POSIX_C_SOURCE=200112L -D__BSD_VISIBLE=1 -Wno-unused-parameter -Wno-implicit-fallthrough -fsanitize=address
CLANG=clang

TARGET_CLIENT := ../client5
TARGET_SERVER := ../socks5d