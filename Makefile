#######################################################################
#
# Copyright (C) 2018-2021 David C. Harrison. All right reserved.
#
# You may not use, distribute, publish, or modify this code without 
# the express written permission of the copyright holder.
#
#######################################################################

include Makefile.libs

CFLAGS = -Wall -Wextra -Iinclude -Llib -pthread 
CC = g++-10 -g -std=c++20

# Assignment No.
a = 8

SRC=$(wildcard src/*.cc)

all: cracker gcracker

cracker: $(SRC)
	$(CC) -O3 -o $@ $^ $(CFLAGS) -lcracker -lcrypt $(LIBS) 2>&1 | tee make.out

gcracker: $(SRC)
	$(CC) -g -o $@ $^ $(CFLAGS) -lcracker -lcrypt $(LIBS) 2>&1 | tee make.out

clean:
	@rm -f cracker gcracker make.out

submit: clean
	@echo ""
	@echo "#### Only these file are submitted:"
	@echo ""
	@tar czvf ~/CSE111-Assignment$(a).tar.gz Makefile.libs src/*
	@echo ""
	@echo "##### Confirming submission is good..."
	@echo ""
	@./confirm.sh $(a)
	@echo ""
	@echo "#### If that failed, fix the problem and try again."
	@echo ""
	@echo "Finally, don't forget to upload ~/CSE111-Assignment$(a).tar.gz to Canvas!"
	@echo ""
