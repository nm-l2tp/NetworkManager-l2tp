AC_PREREQ([2.69])

AC_INIT([NetworkManager-l2tp],
        [1.20.20],
        [https://github.com/nm-l2tp/NetworkManager-l2tp/issues],
        [NetworkManager-l2tp])
AM_INIT_AUTOMAKE([1.9 foreign no-dist-gzip dist-xz -Wno-portability])
AM_MAINTAINER_MODE
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS

dnl
dnl AC_SUBST runstatedir is for autoconf < 2.70 compatibilty
dnl
if test "x$runstatedir" = x; then
	AC_SUBST([runstatedir], ['${localstatedir}/run'])
fi

dnl Prefer gcc-* variants; the ones libtool would choose don't work with LTO
AC_CHECK_TOOLS(AR, [gcc-ar ar], false)
AC_CHECK_TOOLS(RANLIB, [gcc-ranlib ranlib], :)

LT_INIT([disable-static])

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_CPP
AC_PROG_EGREP
AC_PATH_PROG(GLIB_COMPILE_RESOURCES, glib-compile-resources)
PKG_PROG_PKG_CONFIG()

AC_CHECK_PROG([has_file], file, yes, no)
if test x$has_file = xno ; then
	AC_MSG_ERROR(["file" utility not found.])
fi

AC_CHECK_PROG([has_find], find, yes, no)
if test x$has_find = xno ; then
	AC_MSG_ERROR(["find" utility not found.])
fi

dnl
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h paths.h stdarg.h stdbool.h sys/ioctl.h sys/time.h syslog.h unistd.h])

AC_CHECK_HEADERS(pppd/pppd.h,,
  AC_MSG_ERROR(couldn't find pppd.h. pppd development headers are required.))

dnl
dnl Check the presense of other pppd/*.h files
AC_CHECK_HEADERS([pppd/chap.h pppd/chap-new.h pppd/chap_ms.h])

dnl
dnl Versions >= 2.5.0 will have pkg-config support
PKG_CHECK_EXISTS([pppd],
    [AS_VAR_SET([pppd_pkgconfig_support],[yes])])

dnl
dnl Get the version of pppd using pkg-config, assume 2.4.9 if not present
PPPD_VERSION=2.4.9
if test x"$pppd_pkgconfig_support" = xyes; then
    PPPD_VERSION=`$PKG_CONFIG --modversion pppd`
fi

AC_ARG_WITH([pppd-plugin-dir], AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))

if test -n "$with_pppd_plugin_dir" ; then
	PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
	PPPD_PLUGIN_DIR="${libdir}/pppd/$PPPD_VERSION"
fi
AC_SUBST(PPPD_PLUGIN_DIR)

dnl The version of pppd dictates what code can be included, i.e. enable use of
dnl   #if WITH_PPP_VERSION >= PPP_VERSION(2,5,0) in the code
AC_DEFINE_UNQUOTED([PPP_VERSION(x,y,z)],
    [((x & 0xFF) << 16 | (y & 0xFF) << 8 | (z & 0xFF) << 0)],
    [Macro to help determine the particular version of pppd])
PPP_VERSION=$(echo $PPPD_VERSION | sed -e "s/\./\,/g")
AC_DEFINE_UNQUOTED(WITH_PPP_VERSION, PPP_VERSION($PPP_VERSION),
    [The real version of pppd represented as an int])

AC_MSG_CHECKING(whether EAP-TLS patch has been applied to pppd)
AC_EGREP_CPP(eaptls_passwd_hook, [
#define USE_EAPTLS
#include <pppd/pppd.h>
#include <pppd/eap.h>
], [have_eap_tls=yes] , [have_eap_tls=no])

if test "x${have_eap_tls}" = "xno"; then
	AC_MSG_RESULT(no)
	AC_MSG_WARN(EAP-TLS patch has not been applied to pppd)
else
	AC_MSG_RESULT(yes)
	AC_DEFINE(USE_EAPTLS, 1, [Use EAP-TLS pppd patch])
fi

AC_ARG_WITH(nm-ipsec-secrets, AS_HELP_STRING([--with-nm-ipsec-secrets=path], [The main IPSec secrets file, defaults to /etc/ipsec.secrets]), [], [with_nm_ipsec_secrets=])
AS_IF([test -z "$with_nm_ipsec_secrets"], with_nm_ipsec_secrets="/etc/ipsec.secrets")
if (printf '%s' "$with_nm_ipsec_secrets" | grep -v -q '^/'); then
	AC_MSG_ERROR([--with-nm-ipsec-secrets must be an absolute path, instead it is '$with_nm_ipsec_secrets'])
fi
AC_DEFINE_UNQUOTED(NM_IPSEC_SECRETS, "$with_nm_ipsec_secrets", [IPSec secrets file])

AC_ARG_WITH(nm-ipsec-secrets-dir, AS_HELP_STRING([--with-nm-ipsec-secrets-dir=path], [The directory where to put IPSec secrets, defaults to /etc/ipsec.d/]), [], [with_nm_ipsec_secrets_dir=])
AS_IF([test -z "$with_nm_ipsec_secrets_dir"], with_nm_ipsec_secrets_dir="/etc/ipsec.d")
if (printf '%s' "$with_nm_ipsec_secrets_dir" | grep -v -q '^/'); then
	AC_MSG_ERROR([--with-nm-ipsec-secrets-dir must be an absolute path, instead it is '$with_nm_ipsec_secrets_dir'])
fi
AC_DEFINE_UNQUOTED(NM_IPSEC_SECRETS_DIR, "$with_nm_ipsec_secrets_dir", [IPSec secret dir])

AC_ARG_WITH(nm-ipsec-nss-dir, AS_HELP_STRING([--with-nm-ipsec-nss-dir=path], [The directory where Libreswan's NSS db is stored, defaults to /var/lib/ipsec/nss/]), [], [with_nm_ipsec_nss_dir=])
AS_IF([test -z "$with_nm_ipsec_nss_dir"], with_nm_ipsec_nss_dir="/var/lib/ipsec/nss")
if (printf '%s' "$with_nm_ipsec_nss_dir" | grep -v -q '^/'); then
	AC_MSG_ERROR([--with-nm-ipsec-nss-dir must be an absolute path, instead it is '$with_nm_ipsec_nss_dir'])
fi
AC_DEFINE_UNQUOTED(NM_IPSEC_NSS_DIR, "$with_nm_ipsec_nss_dir", [Libreswan NSS db dir])

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_HEADER_TIME

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

GIT_SHA_RECORD(NM_GIT_SHA)

AC_SEARCH_LIBS([dlopen], [dl dld], [], [ac_cv_search_dlopen=])
AC_SUBST([DL_LIBS], "$ac_cv_search_dlopen")

dnl
dnl Libreswan DH2(modp1024) support
dnl Note: Libreswan >= 3.30 is no longer built with DH2
dnl
AC_ARG_ENABLE(libreswan_dh2, AS_HELP_STRING([--enable-libreswan-dh2], [Build NetworkManager-l2tp with DH2(modp1024) in default phase 1 algorithms for Libreswan (default is no)]))
if test "x${enable_libreswan_dh2}" = "xyes"; then
	AC_DEFINE(LIBRESWAN_DH2, 1, [Libreswan DH2 support])
fi

dnl
dnl Checks for NSS and OpenSSL.
dnl
PKG_CHECK_MODULES(OPENSSL, [libcrypto >= 1.1.0], [have_crypto_openssl=yes], [have_crypto_openssl=no])
if test "x${have_crypto_openssl}" = "xno"; then
	AC_MSG_ERROR($OPENSSL_PKG_ERRORS)
fi
PKG_CHECK_MODULES(NSS, [nss], [have_crypto_ipsec_nss=yes], [have_crypto_ipsec_nss=yes])
if test "${have_crypto_ipsec_nss}" = "yes"; then
	# Work around a pkg-config bug (fdo #29801) where exists != usable
	FOO=`$PKG_CONFIG --cflags --libs nss`
	if test x"$?" != "x0"; then
		 have_crypto_ipsec_nss=no
	fi
fi
if test "x${have_crypto_ipsec_nss}" = "xno"; then
	AC_MSG_ERROR($NSS_PKG_ERRORS)
fi

dnl
dnl GNOME support
dnl
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build NetworkManager-l2tp without GNOME support, e.g. vpn service only]), [], [with_gnome_specified=no])
if test "$with_gnome" != no; then
	with_gnome=yes
fi
AM_CONDITIONAL(WITH_GNOME, test "$with_gnome" != no)

AC_ARG_WITH(gtk4, AS_HELP_STRING([--with-gtk4], [Build NetworkManager-l2tp with libnma-gtk4 support]), [], [with_gtk4_specified=no])
if test "$with_gtk4_specified" = no; then
	with_gtk4=no
fi
if test "$with_gtk4" != yes; then
	with_gtk4=no
fi
AM_CONDITIONAL(WITH_GTK4, test "$with_gtk4" != no)

AC_ARG_ENABLE(absolute-paths, AS_HELP_STRING([--enable-absolute-paths], [Use absolute paths to in .name files. Useful for development. (default is no)]))

dnl
dnl translation support
dnl

# FIXME: Remove AM_GNU_GETTEXT_VERSION once autoreconf supports REQUIRE_VERSION
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19.8])
AM_GNU_GETTEXT_REQUIRE_VERSION([0.19.8])

GETTEXT_PACKAGE=NetworkManager-l2tp
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

# gio-unix will require glib and gio
PKG_CHECK_MODULES(GLIB, gio-unix-2.0 >= 2.40)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_40"
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_40"

if test x"$with_gnome" != xno || test x"$with_gtk4" != xno; then
	PKG_CHECK_MODULES(LIBSECRET, libsecret-1 >= 0.18)
fi

if test x"$with_gnome" != xno; then
	PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.16)
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_16"
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_3_16"
	PKG_CHECK_MODULES(LIBNMA, libnma >= 1.8.0)
fi

if test x"$with_gtk4" != xno; then
	PKG_CHECK_MODULES(GTK4, gtk4 >= 4.0)
	GTK4_CFLAGS="$GTK4_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_4_0"
	GTK4_CFLAGS="$GTK4_CFLAGS -DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_4_0"
	PKG_CHECK_MODULES(LIBNMA_GTK4, libnma-gtk4 >= 1.8.33)
fi

PKG_CHECK_MODULES(LIBNM, libnm >= 1.20)
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_20"
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_20"

NM_VPN_SERVICE_DIR=`$PKG_CONFIG --define-variable prefix='\${prefix}' --variable vpnservicedir libnm`
AC_SUBST(NM_VPN_SERVICE_DIR)

NM_COMPILER_WARNINGS
NM_LTO
NM_LD_GC

NM_PLUGIN_DIR="$libdir/NetworkManager"
AC_SUBST(NM_PLUGIN_DIR)
if test x"$enable_absolute_paths" = x"yes"; then
	NM_PLUGIN_DIR_NAME_FILE="$NM_PLUGIN_DIR/"
else
	enable_absolute_paths=no
	NM_PLUGIN_DIR_NAME_FILE=""
fi
AC_SUBST(NM_PLUGIN_DIR_NAME_FILE)

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<dist-version>], [Define the custom version (like distribution package name and revision)]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

AC_CONFIG_FILES([
Makefile
po/Makefile.in
])
AC_OUTPUT

echo ""
echo "Build configuration: "
echo "  --with-dist-version=$ac_distver"
echo "  --with-gnome=$with_gnome"
echo "  --with-gtk4=$with_gtk4"
echo "  --with-pppd-plugin-dir=$PPPD_PLUGIN_DIR"
echo "  --enable-absolute-paths=$enable_absolute_paths"
echo "  --enable-more-warnings=$set_more_warnings"
echo "  --enable-lto=$enable_lto"
echo "  --enable-ld-gc=$enable_ld_gc"
echo ""
