
CFLAGS = -I/usr/local/include -I/home/icholy/Code/src/github.com/moriyoshi/apr-json/include 
LDFLAGS = -laprjson
SRC = mod_authnz_jwt.c sha2.c hmac_sha2.c jwt.c cookies.c

all: build install

build:
	apxs $(CFLAGS) -c $(SRC) $(LDFLAGS)

install:
	sudo apxs -i -a mod_authnz_jwt.la
	sudo service apache2 reload

clean:
	rm -f *.la *.lo *.slo


