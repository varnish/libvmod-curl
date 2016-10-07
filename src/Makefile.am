AM_CPPFLAGS = @VMOD_INCLUDES@

vmoddir = @VMOD_DIR@

vmod_LTLIBRARIES = libvmod_curl.la
libvmod_curl_la_CFLAGS = $(VMOD_INCLUDES) $(CURL_CFLAGS)
libvmod_curl_la_LDFLAGS = -module -export-dynamic -avoid-version -shared \
	$(CURL_LIBS)

libvmod_curl_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_curl.c

dist_man_MANS = vmod_curl.3
MAINTAINERCLEANFILES = $(dist_man_MANS)

vcc_if.c vcc_if.h vmod_curl.man.rst: @VMODTOOL@ $(top_srcdir)/src/vmod_curl.vcc
	@VMODTOOL@ $(top_srcdir)/src/vmod_curl.vcc

vmod_curl.3: vmod_curl.man.rst

%.1 %.2 %.3 %.4 %.5 %.6 %.7 %.8 %.9:
if HAVE_RST2MAN
	${RST2MAN} $< $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif

VTC_LOG_COMPILER = $(VARNISHTEST) -v -Dvmod_topbuild=$(abs_top_builddir)
TEST_EXTENSIONS = .vtc
TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_curl.vcc \
	$(VMOD_TESTS)

CLEANFILES = $(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_curl.man.rst \
	$(builddir)/vmod_curl.rst \
$(dist_man_MANS)
