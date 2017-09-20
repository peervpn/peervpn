CFLAGS+=-O2
LIBS+=-lcrypto -lz

all: peervpn
peervpn: peervpn.o
	$(CC) $(LDFLAGS) peervpn.o $(LIBS) -o $@
peervpn.o: peervpn.c

install:
	install peervpn /usr/local/sbin/peervpn
	install peervpn.conf /etc/peervpn.conf
	install systemd/peervpn.service /etc/systemd/system/peervpn.service
	
clean:
	rm -f peervpn peervpn.o
