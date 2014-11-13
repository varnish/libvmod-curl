Summary: CURL support for Varnish VCL
Name: vmod-curl
Version: 0.2
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
Source0: libvmod-curl.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: varnish >= 4.0, libuv
BuildRequires: make, python-docutils, curl-devel > 7.19.0, libuv-devel

%description
CURL support for Varnish VCL

%prep
%setup -n libvmod-curl

%build
./configure --prefix=/usr/ --docdir='${datarootdir}/doc/%{name}'
make
make check

%install
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/varnis*/vmods/
%doc /usr/share/doc/%{name}/*
%{_mandir}/man?/*

%changelog
* Thu Nov 13 2014 Waldek Kozba <100assc@gmail.com> - 0.2-0.20141113
- Added dependencies for libuv.
* Tue Nov 14 2012 Lasse Karstensen <lasse@varnish-software.com> - 0.1-0.20121114
- Initial version.
