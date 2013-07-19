#
# Makefile.  Generated from Makefile.in by configure.
#


package = getdns
version = 0.320
tarname	= getdns
distdir	= $(tarname)-$(version)

prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin

srcdir = .


default:
	cd common && $(MAKE)

all : default test 

test:
	cd test && $(MAKE) $@

clean:
	cd common && $(MAKE) $@
	cd test && $(MAKE) $@
	rm -f *.o

distclean:
	cd common && $(MAKE) $@
	cd test && $(MAKE) $@
	rm -f libgetdns*.so config.log config.status Makefile
	rm -fR autom4te.cache

$(distdir): FORCE
	mkdir -p $(distdir)/src
	cp $(srcdir)/configure.ac $(distdir)
	cp $(srcdir)/configure $(distdir)
	cp $(srcdir)/Makefile.in $(distdir)
	cp $(srcdir)/src/Makefile.in $(distdir)/src

distcheck: $(distdir).tar.gz
	gzip -cd $(distdir).tar.gz | tar xvf -
	cd $(distdir) && ./configure
	cd $(distdir) && $(MAKE) all
	cd $(distdir) && $(MAKE) check
	cd $(distdir) && $(MAKE) DESTDIR=$${PWD}/_inst install
	cd $(distdir) && $(MAKE) DESTDIR=$${PWD}/_inst uninstall
	@remaining="`find $${PWD}/$(distdir)/_inst -type f | wc -l`"; \
	if test "$${remaining}" -ne	0; then
	  echo "@@@	$${remaining} file(s) remaining	in stage directory!"; \
	  exit 1; \
	fi
	cd $(distdir) && $(MAKE) clean
	rm -rf $(distdir)
	@echo "*** Package $(distdir).tar.gz is ready for distribution"

Makefile: Makefile.in config.status
	./config.status $@

configure.status: configure
	./config.status --recheck

.PHONY: all distclean clean default
