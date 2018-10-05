
.. image:: https://travis-ci.org/varnish/libvmod-curl.svg?branch=master
   :alt: Travis CI badge
   :target: https://travis-ci.org/varnish/libvmod-curl/

This vmod provides cURL bindings for Varnish so you can use Varnish
as an HTTP client and fetch headers and bodies from backends.

WARNING: Using vmod-curl to connect to HTTPS sites is currently unsupported
and may lead to segmentation faults on VCL load/unload. (openssl library
intricacies)

Installation
============

Source releases can be downloaded from:

    https://download.varnish-software.com/libvmod-curl/

Installation requires an installed version of Varnish Cache, including the
development files. Requirements can be found in the `Varnish documentation`_.

.. _`Varnish documentation`: https://www.varnish-cache.org/docs/4.1/installation/install.html#compiling-varnish-from-source
.. _`Varnish Project packages`: https://www.varnish-cache.org/releases/index.html

Source code is built with autotools, you need to install the correct
development packages first.
If you are using the official `Varnish Project packages`_::

    sudo apt install varnish-dev || sudo yum install varnish-devel

If you are using the distro provided packages::

    sudo apt install libvarnishapi-dev || sudo yum install varnish-libs-devel

In both cases, you also need the libcurl development package::

    sudo apt install libcurl4-openssl-dev || sudo yum install libcurl-devel

Then proceed to the configure and build::

    ./configure
    make
    make check   # optional
    sudo make install

The resulting loadable modules (``libvmod_*.so`` files) will be installed to
the Varnish module directory. (default `/usr/lib/varnish/vmods/`)

Usage
=====

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

Development
===========

The source git tree lives on Github: https://github.com/varnish/libvmod-curl

All source code is placed in the master git branch. Pull requests and issue
reporting are appreciated.

Unlike building from releases, you need to first bootstrap the build system
when you work from git. In addition to the dependencies mentioned in the
installation section, you also need to install the build tools::

    sudo apt-get automake autotools-dev python-docutils

Then build the vmod::

    ./autogen.sh
    ./configure
    make
    make check # recommended

If the ``configure`` step succeeds but the ``make`` step fails, check for
warnings in the ``./configure`` output or the ``config.log`` file. You may be
missing bootstrap dependencies not required by release archives.

If you have installed Varnish to a non-standard directory, call ``autogen.sh``
and ``configure`` with ``PKG_CONFIG_PATH`` and ``ACLOCAL_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called with
``--prefix=$PREFIX``, use::

    export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
    export ACLOCAL_PATH=$PREFIX/share/aclocal

--

Development of this VMOD has been sponsored by the Norwegian company
Aspiro Music AS for usage on their WiMP music streaming service.

.. _`Varnish Project packages`: https://www.varnish-cache.org/releases/index.html
