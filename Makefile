OBJDIR = bin

CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -fomit-frame-pointer -flto -Ofast -march=native -mtune=native

all: ctagsparse

$(OBJDIR):
	@mkdir -p $@

ctagsparse: ctagsparse.c | $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $(OBJDIR)/$@