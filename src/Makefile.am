libexec_PROGRAMS = nm-l2tp-service

noinst_LTLIBRARIES = libnm-l2tp-pppd-service-dbus.la

shared_sources = \
    $(top_srcdir)/shared/nm-service-defines.h \
    $(top_srcdir)/shared/nm-utils/nm-shared-utils.c \
    $(top_srcdir)/shared/nm-utils/nm-shared-utils.h \
    $(top_srcdir)/shared/nm-utils/nm-vpn-plugin-macros.h

AM_CPPFLAGS = \
    $(GLIB_CFLAGS) \
    $(LIBNM_CFLAGS) \
    -I"${top_srcdir}/shared/" \
    -DBINDIR=\"$(bindir)\" \
    -DPREFIX=\""$(prefix)"\" \
    -DSYSCONFDIR=\""$(sysconfdir)"\" \
    -DLIBDIR=\""$(libdir)"\" \
    -DLIBEXECDIR=\""$(libexecdir)"\" \
    -DLOCALSTATEDIR=\""$(localstatedir)"\" \
    -DRUNSTATEDIR=\""$(runstatedir)"\" \
    -DDATADIR=\"$(datadir)\" \
    -DNM_L2TP_LOCALEDIR=\"$(datadir)/locale\" \
    -DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\"

###############################################################################

nodist_libnm_l2tp_pppd_service_dbus_la_SOURCES = \
    nm-l2tp-pppd-service-dbus.c \
    nm-l2tp-pppd-service-dbus.h

libnm_l2tp_pppd_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nm-l2tp-pppd-service-dbus.h: $(top_srcdir)/src/nm-l2tp-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

nm-l2tp-pppd-service-dbus.c:
	@true

###############################################################################

nm_l2tp_service_SOURCES = \
    $(shared_sources) \
    nm-l2tp-service.c \
    nm-l2tp-service.h

nm_l2tp_service_LDADD = \
    $(GLIB_LIBS) \
    $(LIBNM_LIBS) \
    libnm-l2tp-pppd-service-dbus.la

###############################################################################

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-l2tp-pppd-plugin.la

nm_l2tp_pppd_plugin_la_SOURCES = \
    $(shared_sources) \
    nm-l2tp-pppd-plugin.c \
    nm-ppp-status.h

nm_l2tp_pppd_plugin_la_CPPFLAGS = \
    -I"$(top_srcdir)/shared/" \
    $(GLIB_CFLAGS) \
    $(LIBNM_CFLAGS)

nm_l2tp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_l2tp_pppd_plugin_la_LIBADD = \
    $(GLIB_LIBS) \
    $(LIBNM_LIBS)

###############################################################################

BUILT_SOURCES = \
    nm-l2tp-pppd-service-dbus.h \
    nm-l2tp-pppd-service-dbus.c

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = \
    nm-l2tp-pppd-service.xml
