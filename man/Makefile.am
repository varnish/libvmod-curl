#

dist_man_MANS = vmod_curl.3
MAINTAINERCLEANFILES = $(dist_man_MANS)

vmod_curl.3: vmod_curl.rst
if HAVE_RST2MAN
	${RST2MAN} vmod_curl.rst $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif
