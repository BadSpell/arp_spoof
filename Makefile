#Makefile
all: arp_spoof

arp_spoof: arp_spoof.o
	g++ -o arp_spoof arp_spoof.o -lpcap 

arp_spoof.o: arp_spoof.cpp
	g++ -c -o arp_spoof.o arp_spoof.cpp -lpcap

clean:
	rm -f arp_spoof
	rm -f *.o