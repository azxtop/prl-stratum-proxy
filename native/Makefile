CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

.PHONY: all clean
all: build/netroute.so

build/netroute.so: netroute.c
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl -pthread

clean:
	rm -f build/netroute.so
