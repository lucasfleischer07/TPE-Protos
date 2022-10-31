include ../Makefile.inc

SOURCES_CLIENT := $(wildcard client/*.c)
SOURCES_SERVER := $(wildcard server/*.c)
SOURCES_UTILS := $(wildcard utils/*.c)

OBJECTS_CLIENT := client.o $(SOURCES_CLIENT:.c=.o)
OBJECTS_SERVER := server.o $(SOURCES_SERVER:.c=.o)
OBJECTS_UTILS := $(SOURCES_UTILS:.c=.o)
OBJECTS := $(OBJECTS_CLIENT) $(OBJECTS_SERVER) $(OBJECTS_UTILS)

TARGETS := $(TARGET_SERVER) $(TARGET_CLIENT) 

all: server client
	@echo -e "\e[1;3;36m[src compiled]\e[0m"


server: $(OBJECTS_SERVER) $(OBJECTS_UTILS)
	@$(GCC) $(GCC_FLAGS) $(OBJECTS_SERVER) $(OBJECTS_UTILS) -o $(TARGET_SERVER)
	@echo -e "\e[3;36m[Server compiled]\e[0m"


client: $(OBJECTS_CLIENT) $(OBJECTS_UTILS)
	@$(GCC) $(GCC_FLAGS) $(OBJECTS_CLIENT) $(OBJECTS_UTILS) -o $(TARGET_CLIENT)
	@echo -e "\e[3;36m[Client compiled]\e[0m"


%.o: %.c
	@$(GCC) $(GCC_FLAGS) -I./include -I./client -I./server -I./utils -c $< -o $@
	@echo -e "\e[32m[Compiled object file]\e[0m $@"


clean:
	-@rm -rf $(OBJECTS) $(TARGETS)
	@echo -e "\e[3;35m[src cleaned]\e[0m"
