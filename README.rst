
.. image:: https://travis-ci.org/varnish/libvmod-curl.svg?branch=4.1
   :alt: Travis CI badge
   :target: https://travis-ci.org/varnish/libvmod-curl/

This vmod provides cURL bindings for Varnish so you can use Varnish
as an HTTP client and fetch headers and bodies from backends.

WARNING: Using vmod-curl to connect to HTTPS sites is currently unsupported
and may lead to segmentation faults on VCL load/unload. (openssl library
intricacies)

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called
with ``--prefix=$PREFIX``, use

::

    PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
    export PKG_CONFIG_PATH

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``

To use the vmod do something along the lines of::

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
