CC = $(CROSS_COMPILE)gcc
OBJS = wificurse.o iw.o dev.o error.o console.o

all: wificurse

wificurse: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -f *~ *.o wificurse
