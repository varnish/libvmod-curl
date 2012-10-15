=================
vmod_curl
=================

-------------------
Varnish cURL Module
-------------------

:Author: Olivier Favre
:Date: 2013-01-27
:Version: 0.2
:Manual section: 3

SYNOPSIS
========

import curl;

DESCRIPTION
===========

Varnish Module that provides cURL bindings for Varnish so you can use
Varnish as an HTTP client and fetch headers and bodies from backends.

FUNCTIONS
=========

fetch
-----

Prototype
        ::
                fetch(STRING)
Return value
        VOID
Description
        Performs a cURL request to the given URL.
Example
        ::
                curl.fetch("http://example.com/test");
                curl.free();

header
------

Prototype
        ::
                header(STRING)
Return value
        STRING
Description
        Returns the header named in the first argument.
Example
        ::
                curl.fetch("http://example.com/test");
                if (curl.header("X-Foo") == "bar") {
                // ...
                }
                curl.free();

free
----

Prototype
        ::
                free()
Return value
        VOID
Description
        Free the memory used by headers.
        Not needed, will be handled automatically if it's not called.

status
------

Prototype
        ::
                status()
Return value
        INT
Description
        Returns the HTTP status code.
Example
        ::
                curl.fetch("http://example.com/test");
                if (curl.status() == 404) {
                // ...
                }
                curl.free();

error
-----

Prototype
        ::
                error()
Return value
        STRING
Description
        Returns the HTTP error.

body
----

Prototype
        ::
                body()
Return value
        STRING
Description
        Returns the HTTP body content.

set_timeout
-----------

Prototype
        ::
                set_timeout(INT)
Return value
        VOID
Description
        Sets the CURLOPT_TIMEOUT_MS option to the value of the first argument.

set_connect_timeout
-------------------

Prototype
        ::
                set_connect_timeout(INT)
Return value
        VOID
Description
        Sets the CURLOPT_CONNECTTIMEOUT_MS option to the value of the first argument.

set_ssl_verify_peer
-------------------

Prototype
        ::
                set_ssl_verify_peer(INT)
Return value
        VOID
Description
        Sets the CURLOPT_SSL_VERIFYPEER option to either 0L or 1L, depending on the boolean value of the first argument.

set_ssl_verify_host
-------------------

Prototype
        ::
                set_ssl_verify_host(INT)
Return value
        VOID
Description
        Sets the CURLOPT_SSL_VERIFYHOST option to either 0L or 1L, depending on the boolean value of the first argument.

set_ssl_cafile
--------------

Prototype
        ::
                set_ssl_cafile(STRING)
Return value
        VOID
Description
        Sets the CURLOPT_CAINFO option to the value of the first argument.

set_ssl_capath
--------------

Prototype
        ::
                set_ssl_capath(STRING)
Return value
        VOID
Description
        Sets the CURLOPT_CAPATH option to the value of the first argument.

add_header
----------

Prototype
        ::
                add_header(STRING)
Return value
        VOID
Description
        Adds a custom request header

unset_header
------------

Prototype
        ::
                unset_header(STRING)
Return value
        VOID
Description
        Removes all custom request header fields matching the given header name

escape
------

Prototype
        ::
                escape(STRING)
Return value
        STRING
Description
        URL encodes the given string.

unescape
--------

Prototype
        ::
                unescape(STRING)
Return value
        STRING
Description
        URL decodes the given string.

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

Usage::

 ./configure VARNISHSRC=DIR [VMODDIR=DIR]

`VARNISHSRC` is the directory of the Varnish source tree for which to
compile your vmod. Both the `VARNISHSRC` and `VARNISHSRC/include`
will be added to the include search paths for your module.

Optionally you can also set the vmod install directory by adding
`VMODDIR=DIR` (defaults to the pkg-config discovered directory from your
Varnish installation).

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``

Note that some of the test cases /will/ and should fail at the time being.

In your VCL you could then use this vmod along the following lines::
        
        import curl;

        sub vcl_recv {
                if (req.http.X-Curl) {
                        curl.fetch(req.http.X-Curl);
                        if (curl.status() != 200) {
                                return (error);
                        }
                }
                // ...
        }

HISTORY
=======

0.2: More stuff!

0.1: Initial version.

BUGS
====

None.

COPYRIGHT
=========

Development of this VMOD has been sponsored by the Norwegian company
Aspiro Music AS for usage on their WiMP music streaming service.

This document is licensed under the same license as the
libvmod-curl project. See LICENSE for details.

* Copyright (c) 2011 Varnish Software
