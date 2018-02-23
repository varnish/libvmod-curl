
This is a running log of changes to libvmod-curl.

libvmod-curl 1.0.4 (2018-03-07)
-------------------------------

* Add unix domain socket support

* Skip Content-Length when calling header_add_all()

* Skip Transfer-Encoding

* More debug flags: logging headers and bodies

* Added compatibility with Varnish Cache 6.0

This release was tested with Varnish Cache 4.1.9 and trunk (2018-03-07)


libvmod-curl 1.0.3 (2016-04-27)
-------------------------------

* [autoconf] README and CHANGES files are now installed.

Bugfix:

* Use VTAILQ_REMOVE_SAFE when removing headers.

This release was tested with Varnish Cache 4.1.2.


libvmod-curl 1.0.2 (2016-03-14)
-------------------------------

* Code was ported to Varnish Cache 4.1 format.

* Minor improvements to the documentation.

Bugfixes:

* Add all headers from a req or bereq object (Issue #33)

This release was tested with Varnish Cache 4.1.2.


libvmod-curl 1.0.1 (2015-04-21)
-------------------------------

This release was made before the introduction of the changes file.

