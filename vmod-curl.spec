Summary: CURL support for Varnish VCL
Name: vmod-curl
Version: 1.0.1
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
Source0: libvmod-curl.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: varnish >= 4.0.2
BuildRequires: make
BuildRequires: python-docutils
BuildRequires: varnish >= 4.0.2
BuildRequires: varnish-libs-devel >= 4.0.2
BuildRequires: curl-devel > 7.19.0

%description
CURL support for Varnish VCL

%prep
%setup -n libvmod-curl-%{version}

%build
./configure --prefix=/usr/ --docdir='${datarootdir}/doc/%{name}'
make
make check

%install
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/usr/share/doc/%{name}/
cp README.rst %{buildroot}/usr/share/doc/%{name}/
cp LICENSE %{buildroot}/usr/share/doc/%{name}/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/varnis*/vmods/
%doc /usr/share/doc/%{name}/*
%{_mandir}/man?/*

%changelog
* Tue Apr 21 2015 Dag Haavi Finstad <daghf@varnish-software.com> - 1.0.1
- Varnish 4.0 support.
* Tue Nov 14 2012 Lasse Karstensen <lasse@varnish-software.com> - 0.1-0.20121114
- Initial version.
