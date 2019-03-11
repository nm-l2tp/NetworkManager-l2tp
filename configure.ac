AC_PREREQ(2.59)

AC_INIT(NetworkManager-l2tp,
        1.0.12,
        https://github.com/nm-l2tp/network-manager-l2tp/issues,
        NetworkManager-l2tp)
AM_INIT_AUTOMAKE([1.9 foreign no-dist-gzip dist-bzip2 subdir-objects])
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

dnl
dnl AC_SUBST runstatedir is for autoconf < 2.70 compatibilty
dnl
if test "x$runstatedir" = x; then
	AC_SUBST([runstatedir], ['${localstatedir}/run'])
fi

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

dnl
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

AC_CHECK_HEADERS(pppd/pppd.h,,
  AC_MSG_ERROR(couldn't find pppd.h. pppd development headers are required.))

AC_CHECK_HEADERS(nm-vpn-password-dialog.h)
AM_CONDITIONAL([HAVE_NM_VPN_PASSWORD_DIALOG_H], [test "x$ac_cv_header_nm_vpn_password_dialog_h" = xyes])

AC_ARG_WITH([pppd-plugin-dir], AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))

if test -n "$with_pppd_plugin_dir" ; then
	PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
	PPPD_PLUGIN_DIR="${libdir}/pppd/2.4.5"
fi
AC_SUBST(PPPD_PLUGIN_DIR)

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

dnl
dnl GNOME support
dnl
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build NetworkManager-l2tp without GNOME support, e.g. vpn service only]))
AM_CONDITIONAL(WITH_GNOME, test x"$with_gnome" != xno)

GETTEXT_PACKAGE=NetworkManager-l2tp
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.32)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32"

PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1 >= 0.74)

PKG_CHECK_MODULES(NM,
                  NetworkManager >= 0.9.8
                  libnm-util >= 0.9.8
                  libnm-glib >= 0.9.8
                  libnm-glib-vpn >= 0.9.8)

if test x"$with_gnome" != xno; then
	PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.4)
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_4"

	PKG_CHECK_MODULES(LIBSECRET, libsecret-unstable)
	PKG_CHECK_MODULES(NMGTK, libnm-gtk )
	AC_CHECK_LIB(nm-gtk, nma_utils_setup_password_storage,, AC_DEFINE([NEED_PASSWORD_STORAGE_ICON],1,[Define to 1 if missing password, storage and icon functions in libnm-gtk]))
fi

NM_COMPILER_WARNINGS

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<dist-version>], [Define the custom version (like distribution package name and revision)]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

AC_CONFIG_FILES([
Makefile
src/Makefile
auth-dialog/Makefile
properties/Makefile
po/Makefile.in
])
AC_OUTPUT
