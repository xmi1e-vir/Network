# Linker flags for pcap library
LDLIBS += -lpcap

# Default target
all: pcap-test

# Build the target executable
pcap-test: pcap-test.c
	$(CC) $(CFLAGS) -o pcap-test pcap-test.c $(LDLIBS)

# Clean up build artifacts
clean:
	rm -f pcap-test *.o

# PHONY targets are not actual files
.PHONY: all clean
