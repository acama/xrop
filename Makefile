default: xrp

INSTALL_DIR = /opt/xrop

xrp:
	mkdir -p build/lib
	cd src && $(MAKE)

install: xrp
	mkdir -p $(INSTALL_DIR)
	cp -r build $(INSTALL_DIR)
	cp xrop $(INSTALL_DIR)
	ln -sf /opt/xrop/xrop /usr/local/bin/

clean:
	cd  src && $(MAKE) clean
	rm -rf build
