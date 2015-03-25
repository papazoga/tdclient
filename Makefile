OBJS=l2tp.o client.o
CFLAGS=-I/usr/include/libnl3
LIBS=-lnl-3 -lnl-genl-3 -lrt

all: client

client: $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o client

clean:
	rm -f client *.o
