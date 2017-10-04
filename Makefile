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
	rm -rf ./root/
	rm -f *.deb

deb: peervpn
	mkdir -p root/usr/bin/
	cp peervpn root/usr/bin/
	mkdir -p root/usr/share/doc/peervpn
	cp README.md root/usr/share/doc/peervpn/README.md
	cp peervpn.conf root/usr/share/doc/peervpn/peervpn.conf.example
	mkdir -p root/etc/peervpn
	cp peervpn.conf root/etc/peervpn/peervpn.conf
	mkdir -p root/lib/systemd/system
	cp systemd/peervpn@.service root/lib/systemd/system/peervpn@.service
	fpm -s dir \
	    -t deb \
            -v 0.044 \
            -n peervpn \
	    -a all \
            --prefix / \
            --after-install postinst.sh \
            -C root/ .
