PREFIX ?= /usr/local
CC = $(CROSS_COMPILE)gcc
OBJS = src/wificurse.o src/iw.o src/dev.o src/error.o src/console.o

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
