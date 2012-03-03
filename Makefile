PREFIX ?= /usr/local
CC = $(CROSS_COMPILE)gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:%.c=%.o)

.PHONY: clean all install

ifneq ($(DESTDIR),)
    INSTALLDIR = $(subst //,/,$(DESTDIR)/$(PREFIX))
else
    INSTALLDIR = $(PREFIX)
endif


all: wificurse

wificurse: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: all
	@mkdir -p $(INSTALLDIR)/bin
	cp wificurse $(INSTALLDIR)/bin/wificurse

clean:
	@rm -f src/*~ src/\#*\# src/*.o *~ \#*\# wificurse
