PREFIX ?= /usr
CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -pthread

SRCS = $(wildcard src/*.c)
HDRS = $(wildcard src/*.h)

OBJS = $(SRCS:%.c=%.o)
LIBS = 

.PHONY: clean all install

ifneq ($(DESTDIR),)
    INSTALLDIR = $(subst //,/,$(DESTDIR)/$(PREFIX))
else
    INSTALLDIR = $(PREFIX)
endif


all: wificurse

wificurse: $(OBJS)
	$(CC) ${CFLAGS} $(LDFLAGS) $(LIBS) $(OBJS) -o $@

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	@mkdir -p $(INSTALLDIR)/bin
	cp wificurse $(INSTALLDIR)/bin/wificurse

clean:
	@rm -f src/*~ src/\#*\# src/*.o *~ \#*\# wificurse
