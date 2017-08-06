AC_PREREQ(2.60)

AC_INIT(NetworkManager-l2tp,
        1.2.8,
        https://github.com/nm-l2tp/network-manager-l2tp/issues,
        NetworkManager-l2tp)
AM_INIT_AUTOMAKE([1.9 foreign no-dist-gzip dist-xz])
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
AC_PROG_LIBTOOL

dnl
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

AC_CHECK_HEADERS(pppd/pppd.h,,
  AC_MSG_ERROR(couldn't find pppd.h. pppd development headers are required.))

AC_ARG_WITH([pppd-plugin-dir], AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))

if test -n "$with_pppd_plugin_dir" ; then
	PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
	PPPD_PLUGIN_DIR="${libdir}/pppd/2.4.7"
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

GIT_SHA_RECORD(NM_GIT_SHA)

AC_SEARCH_LIBS([dlopen], [dl dld], [], [ac_cv_search_dlopen=])
AC_SUBST([DL_LIBS], "$ac_cv_search_dlopen")

dnl
dnl GNOME support
dnl
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build NetworkManager-l2tp without GNOME support, e.g. vpn service only]), [], [with_gnome_specified=no])
AC_ARG_WITH(libnm-glib, AS_HELP_STRING([--without-libnm-glib], [Build NetworkManager-l2tp without libnm-glib comatibility]), [], [with_libnm_glib_specified=no])
if test "$with_libnm_glib_specified" != no -a "$with_libnm_glib" != no; then
	if test "$with_gnome_specified" != no -a "$with_gnome" == no; then
		AC_MSG_ERROR(Building --with-libnm-glib conflicts with --without-gnome)
	fi
fi
if test "$with_gnome" != no; then
	with_gnome=yes
fi
if test "$with_libnm_glib_specified" == no; then
	with_libnm_glib="$with_gnome"
fi
if test "$with_libnm_glib" != no; then
	with_libnm_glib=yes
fi
AM_CONDITIONAL(WITH_GNOME, test "$with_gnome" != no)
AM_CONDITIONAL(WITH_LIBNM_GLIB, test "$with_libnm_glib" != no)

AC_ARG_ENABLE(absolute-paths, AS_HELP_STRING([--enable-absolute-paths], [Use absolute paths to in .name files. Useful for development. (default is no)]))

GETTEXT_PACKAGE=NetworkManager-l2tp
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

# gio-unix will require glib and gio
PKG_CHECK_MODULES(GLIB, gio-unix-2.0 >= 2.32)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32"

if test x"$with_gnome" != xno; then
	PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.4)
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_4"

	PKG_CHECK_MODULES(LIBNMA, libnma >= 1.2.0)
	PKG_CHECK_MODULES(LIBSECRET, libsecret-1 >= 0.18)

	if test x"$with_libnm_glib" != xno; then
		PKG_CHECK_MODULES(LIBNM_GTK, libnm-gtk >= 1.2.0)
		PKG_CHECK_MODULES(LIBNM_GLIB,
			NetworkManager >= 1.2.0
			libnm-util >= 1.2.0
			libnm-glib >= 1.2.0
			libnm-glib-vpn >= 1.2.0);

		LIBNM_GLIB_CFLAGS="$LIBNM_GLIB_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_2"
		LIBNM_GLIB_CFLAGS="$LIBNM_GLIB_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_2"
	fi
fi

PKG_CHECK_MODULES(LIBNM, libnm >= 1.2.0)
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_2"
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_2"

NM_VPN_SERVICE_DIR=`$PKG_CONFIG --define-variable prefix='\${prefix}' --variable vpnservicedir libnm`
AC_SUBST(NM_VPN_SERVICE_DIR)

NM_COMPILER_WARNINGS
NM_LTO
NM_LD_GC

NM_PLUGIN_DIR="$libdir/NetworkManager"
AC_SUBST(NM_PLUGIN_DIR)
if test x"$enable_absolute_paths" == x"yes"; then
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
echo "  --with-libnm-glib=$with_libnm_glib"
echo "  --with-pppd-plugin-dir=$PPPD_PLUGIN_DIR"
echo "  --enable-absolute-paths=$enable_absolute_paths"
echo "  --enable-more-warnings=$set_more_warnings"
echo "  --enable-lto=$enable_lto"
echo "  --enable-ld-gc=$enable_ld_gc"
echo ""
