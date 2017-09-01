CFLAGS+=-O2
LIBS+=-lcrypto -lz

all: peervpn
peervpn: peervpn.o
	$(CC) $(LDFLAGS) peervpn.o $(LIBS) -o $@
peervpn.o: peervpn.c

install:
	install peervpn /usr/local/sbin/peervpn
	install peervpn.service /lib/systemd/system/peervpn.service
	install peervpn-sample.conf /usr/local/etc/peervpn.conf
clean:
	rm -f peervpn peervpn.o
