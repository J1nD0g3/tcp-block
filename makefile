LDLIBS += -lpcap

all: tcp-block

tcp-block: tcp-block.c

clean:
	rm -f tcp-block *.o

