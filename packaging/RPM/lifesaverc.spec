Name:           lifesaverc
Version:        1.1
Release:        1%{?dist}
Summary:        A backup program written in C.

License:        GPLv3+
URL:            https://github.com/Thynkon/%{name}
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  cmake
BuildRequires:  libarchive-devel
BuildRequires:  libssh-devel

%description
lifesaverc is a C program that compresses a file/directory
and sends it to a backup server through a ssh tunnel.
For further details read the README.md file.

%prep
%autosetup


%build
%cmake .
%make_build


%install
rm -rf $RPM_BUILD_ROOT
%make_install


%files
%{_bindir}/%{name}
%license LICENSE
%doc README.md


%changelog
* Thu Mar 12 2020 thynkon <marioferreira2110@gmail.com>
- Build lifesaverc with cmake instead of autotools.
