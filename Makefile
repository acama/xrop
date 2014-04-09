default: xrp

xrp:
	mkdir -p build/lib
	cd src && $(MAKE)

withstatic:
	mkdir -p build/lib
	cd src && $(MAKE) withstatic

clean:
	cd  src && $(MAKE) clean
	rm -rf build
