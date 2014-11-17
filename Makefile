default: xrp

xrp:
	cd src && $(MAKE)

clean:
	cd  src && $(MAKE) clean
	rm -rf build
