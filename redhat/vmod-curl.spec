# %define VARNISHVER 3.0.3
Summary: CURL support for Varnish VCL
Name: vmod-varnish-%{VARNISHVER}-curl
Version: 0.1
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
Source0: ./libvmod-curl.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
# we need EPEL, or at least mhash + mhash-devel from it:
# rpm -Uvh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-7.noarch.rpm
Requires: varnish > 3.0
BuildRequires: make, python-docutils, curl-devel > 7.19.0

%description
libvmod-curl

%prep
%setup -n libvmod-curl

%build
# this assumes that VARNISHSRC is defined on the rpmbuild command line, like this:
# rpmbuild -bb --define 'VARNISHSRC /home/user/rpmbuild/BUILD/varnish-3.0.3' redhat/*spec
./configure VARNISHSRC=%{VARNISHSRC} VMODDIR="$(PKG_CONFIG_PATH=%{VARNISHSRC} pkg-config --variable=vmoddir varnishapi)" --prefix=/usr/
make

%install
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/usr/share/doc/%{name}/
cp README %{buildroot}/usr/share/doc/%{name}/
cp LICENSE %{buildroot}/usr/share/doc/%{name}/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
# /opt/varnish/lib/varnish/vmods/
/usr/lib64/varnish/vmods/
%doc /usr/share/doc/%{name}/*

%if "%{RHVERSION}" == "EL5"
/usr/man/man?/*
%else
/usr/share/man/man?/*
%endif

%changelog
* Wed Oct 03 2012 Lasse Karstensen <lasse@varnish-software.com> - 0.1-0.20120918
- Initial version.
