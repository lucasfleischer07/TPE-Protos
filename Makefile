include Makefile.inc

all: 
	@cd src; make all
	@echo -e "\e[1;3;36m[Project compiled] \e[0m"

clean:
	@cd src; make clean
	@echo -e '\e[1;3;35m[Project cleaned] \e[0m'

recompile:
	@make clean; make all


.PHONY: all clean recompile