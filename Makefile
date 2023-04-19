default: xrp

INSTALL_DIR = /opt/xrop

xrp:
	mkdir -p lib
	cd src && $(MAKE)

install: xrp
	mkdir -p $(INSTALL_DIR)
	cp -r lib $(INSTALL_DIR)
	cp xrop $(INSTALL_DIR)
	ln -sf /opt/xrop/xrop /usr/local/bin/

uninstall:
	rm -rf /opt/xrop
	rm /usr/local/bin/xrop

clean:
	cd  src && $(MAKE) clean
	rm -rf lib
