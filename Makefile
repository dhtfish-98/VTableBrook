CC ?= clang
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -O2
PREFIX ?= /usr/local

.PHONY: all clean install
all: vtablebrook

vtablebrook: Sources/vtb_container_walk.c Sources/vtb_class_walk.c Sources/vtb_pipeline.c Sources/vtb_bootstrap.c Sources/vtb_image_layout.h
	$(CC) $(CFLAGS) Sources/vtb_container_walk.c Sources/vtb_class_walk.c Sources/vtb_pipeline.c Sources/vtb_bootstrap.c -o $@

clean:
	$(RM) vtablebrook

install: vtablebrook
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 vtablebrook $(DESTDIR)$(PREFIX)/bin/
