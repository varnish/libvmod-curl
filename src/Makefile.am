AM_CFLAGS = $(VARNISHAPI_CFLAGS)

# Modules

vmod_LTLIBRARIES = \
	libvmod_curl.la

libvmod_curl_la_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS)
libvmod_curl_la_LDFLAGS = $(VMOD_LDFLAGS) $(CURL_LIBS)
libvmod_curl_la_SOURCES = \
	vmod_curl.c \
	debug_flags.h
nodist_libvmod_curl_la_SOURCES = \
	vcc_curl_if.c \
	vcc_curl_if.h

@BUILD_VMOD_CURL@

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -lv
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VARNISHAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VARNISHAPI_VMODDIR)"
TESTS = @VMOD_TESTS@

# Documentation

dist_doc_DATA = \
	vmod_curl.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_curl.3


.rst.1:
	$(AM_V_GEN) $(RST2MAN) $< $@
