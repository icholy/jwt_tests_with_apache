
all: build install

build:
	apxs -I/usr/local/include -I/usr/local/include/josec-0.11 -c mod_authnz_jwt.c -ljansson -ljosec 

install:
	sudo apxs -i -a mod_authnz_jwt.la
	sudo service apache2 reload

clean:
	rm -f mod_authnz_jwt.la mod_authnz_jwt.lo mod_authnz_jwt.slo


