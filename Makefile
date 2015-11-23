
all: build install

build:
	apxs -I/usr/local/include -I/usr/local/include/josec-0.11 -I/home/icholy/Code/src/github.com/moriyoshi/apr-json/include -c mod_authnz_jwt.c jwt.c cookies.c -ljansson -ljosec -laprjson

install:
	sudo apxs -i -a mod_authnz_jwt.la
	sudo service apache2 reload

clean:
	rm -f *.la *.lo *.slo


