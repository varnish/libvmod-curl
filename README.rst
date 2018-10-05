
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

Source code is built with autotools, you need to install the correct build
system and libcurl development packages first::

    sudo apt-get install make libedit-dev libjemalloc-dev libncurses5-dev libpcre3-dev libtool pkg-config python-docutils libcurl4-openssl-dev

Then you need the Varnish development package.

If you are using the official `Varnish Project packages`_::

    sudo apt-get install varnish-dev || sudo yum install varnish-devel

If you are using the distro provided packages::

    sudo apt-get install libvarnishapi-dev || sudo yum install varnish-libs-devel

Then proceed to the configure and build::

    ./configure
    make
    make check   # optional
    sudo make install

The resulting loadable modules (``libvmod_foo*.so`` files) will be installed to
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

The source git tree lives on Github: https://github.com/varnish/varnish-modules

All source code is placed in the master git branch. Pull requests and issue
reporting are appreciated.

Unlike building from releases, you need to first bootstrap the build system
when you work from git. In addition to the dependencies mentioned in the
installation section, you also need to install the build tools::

    sudo apt-get automake autotools-dev

Then build the vmod::

    ./bootstrap
    ./configure
    make
    make check # recommended
    make install

If the ``configure`` step succeeds but the ``make`` step fails, check for
warnings in the ``./configure`` output or the ``config.log`` file. You may be
missing bootstrap dependencies not required by release archives.

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called
with ``--prefix=$PREFIX``, use

::

    PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
    export PKG_CONFIG_PATH

The process to build the library is:

    sh autogen.sh
    ./configure
    make

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``

--

Development of this VMOD has been sponsored by the Norwegian company
Aspiro Music AS for usage on their WiMP music streaming service.

.. _`Varnish Project packages`: https://www.varnish-cache.org/releases/index.html
