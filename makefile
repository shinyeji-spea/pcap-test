LDLIBS += -lpcap

all:pcap-yeji

pcap-test:pcap-yeji.c

clean:
	rm -f pcap-yeji *.o



