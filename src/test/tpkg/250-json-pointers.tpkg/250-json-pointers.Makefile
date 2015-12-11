builddir = @BUILDDIR@
testname = @TPKG_NAME@
LIBTOOL  = $(builddir)/libtool

CFLAGS=-I$(builddir)/src
LDLIBS=$(builddir)/src/libgetdns.la

.SUFFIXES: .c .o .a .lo .h

.c.lo:
	$(LIBTOOL) --quiet --tag=CC --mode=compile $(CC) $(CFLAGS) -c $< -o $@

$(testname): $(testname).lo
	$(LIBTOOL) --tag=CC --mode=link $(CC) $(LDLIBS) $(LDFLAGS) -o $@ $<

