CFLAGS := -g -Wall -Wextra -Werror -pedantic --std=c99 `pcap-config --cflags`
LDFLAGS := -g `pcap-config --libs`

OBJ = main.o link.o ether.o util.o protocol.o udp.o
BIN = main

$(BIN): $(OBJ)

ether.o: ether.c ether.h vlan.h protocol.h util.h
link.o: link.c aftypes.h ether.h link.h util.h
main.o: main.c aftypes.h link.h util.h
protocol.o: protocol.c protocol.h udp.h util.h
udp.o: udp.c dns.h udp.h util.h link.h vxlan.h
util.o: util.c util.h

.PHONY: clean
clean:
	$(RM) $(OBJ) $(BIN)
