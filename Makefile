CC=gcc

all: clean build

default: build

build: server.c client.c transport.c io.c security.c sec.c 
	${CC} -o server server.c transport.c io.c security.c sec.c ${CFLAGS} ${LDFLAGS}
	${CC} -o client client.c transport.c io.c security.c sec.c ${CFLAGS} ${LDFLAGS}

clean:
	rm -rf server client *.bin *.out *.dSYM *.zip