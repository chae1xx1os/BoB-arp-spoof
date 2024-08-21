LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp
	$(CXX) -c main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp
	$(CXX) -c arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp
	$(CXX) -c ethhdr.cpp

ip.o: ip.h ip.cpp
	$(CXX) -c ip.cpp

mac.o : mac.h mac.cpp
	$(CXX) -c mac.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
