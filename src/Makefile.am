AM_CPPFLAGS = @VMOD_INCLUDES@

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_curl.la

libvmod_curl_la_CFLAGS = @CURL_CFLAGS@
libvmod_curl_la_LDFLAGS = -module -export-dynamic -avoid-version @CURL_LIBS@

libvmod_curl_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_curl.c \
	vmod_curl.h

vcc_if.c vcc_if.h: @VMODTOOL@ $(top_srcdir)/src/vmod_curl.vcc
	@PYTHON@ @VMODTOOL@ $(top_srcdir)/src/vmod_curl.vcc

VMOD_TESTS = tests/*.vtc
.PHONY: $(VMOD_TESTS)

tests/*.vtc:
	@VARNISHTEST@ -Dvarnishd=@VARNISHD@ -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_curl.vcc \
	$(VMOD_TESTS)

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h \
	$(builddir)/vmod_curl.man.rst \
	$(builddir)/vmod_curl.rst
