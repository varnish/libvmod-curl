This vmod provides cURL bindings for Varnish so you can use Varnish
as an HTTP client and fetch headers and bodies from backends.

WARNING: a temporary workaround to allow using the VMOD in 'vcl_backend_.*'
subroutines has been added (see https://github.com/varnish/libvmod-curl/issues/23).
The VMOD behaves as usual, but you should always complete execution of each
cURL request during a single VCL phase (i.e. vcl_recv, vcl_backed_response,
vcl_deliver, etc.). Otherwise, some unexpected behavior may arise. Anyway,
this is the usual approach when using the VMOD.

WARNING: Using vmod-curl to connect to HTTPS sites is currently unsupported
and may lead to segmentation faults on VCL load/unload. (openssl library
intricacies)

INSTALLATION
============
The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``

To use the vmod do something along the lines of:

	import curl;

	sub vcl_recv {
		curl.get("http://example.com/test");
		if (curl.header("X-Foo") == "bar") {
		...
		}
		curl.free();
	}

See src/vmod_curl.vcc for the rest of the callable functions.

Development of this VMOD has been sponsored by the Norwegian company
Aspiro Music AS for usage on their WiMP music streaming service.
