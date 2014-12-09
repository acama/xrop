default: xrp

xrp:
	mkdir -p build/lib
	cd src && $(MAKE)

clean:
	cd  src && $(MAKE) clean
	rm -rf build
