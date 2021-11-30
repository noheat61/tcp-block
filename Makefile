LDLIBS=-lpcap -lpthread

all: tcp-block

tcp-block: main.o ethhdr.o iphdr.o tcphdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o