CFLAGS?=-g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
override CFLAGS:=-Wall -Wno-switch -Wextra $(CFLAGS) -Imblaze
LDLIBS=-lrt

OS := $(shell uname)

ifeq ($(OS),OpenBSD)
LOCALBASE=/usr/local
override CFLAGS+=-I$(LOCALBASE)/include -pthread
LDLIBS=-L$(LOCALBASE)/lib -liconv -pthread
endif

ifeq ($(OS),Darwin)
LDLIBS=-liconv
endif

DESTDIR=
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man

ALL = mvi
SCRIPT = 

all: $(ALL)

VPATH+=mblaze

$(ALL) : % : %.o
mvi : blaze822.o mymemmem.o mytimegm.o seq.o slurp.o
mvi : cmd.o term.o sbuf.o vseq.o ex.o

README: man/mvi.1
	mandoc -Tutf8 $< | col -bx >$@

clean: FRC
	-rm -f $(ALL) *.o

check: FRC all
	PATH=$$(pwd):$$PATH prove -v

install: FRC all
	mkdir -p $(DESTDIR)$(BINDIR) \
		$(DESTDIR)$(MANDIR)/man1 \
		$(DESTDIR)$(MANDIR)/man5 \
		$(DESTDIR)$(MANDIR)/man7
	install -m0755 $(ALL) $(SCRIPT) $(DESTDIR)$(BINDIR)
	install -m0644 man/*.1 $(DESTDIR)$(MANDIR)/man1
	install -m0644 man/*.5 $(DESTDIR)$(MANDIR)/man5
	install -m0644 man/*.7 $(DESTDIR)$(MANDIR)/man7

release:
	VERSION=$$(git describe --tags | sed 's/^v//;s/-[^.]*$$//') && \
	git archive --prefix=mblaze-$$VERSION/ -o mblaze-$$VERSION.tar.gz HEAD

sign:
	VERSION=$$(git describe --tags | sed 's/^v//;s/-[^.]*$$//') && \
	gpg --armor --detach-sign mblaze-$$VERSION.tar.gz && \
	signify -S -s ~/.signify/mblaze.sec -m mblaze-$$VERSION.tar.gz && \
	sed -i '1cuntrusted comment: verify with mblaze.pub' mblaze-$$VERSION.tar.gz.sig

FRC:
