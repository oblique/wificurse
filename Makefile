CC = $(CROSS_COMPILE)gcc
OBJS = wificurse.o error.o

all: wificurse

wificurse: $(OBJS)
	$(CC) -o $@ $^

%.o: %.c %.h
	$(CC) -c -o $@ $<

clean:
	@rm -f *~ *.o wificurse
