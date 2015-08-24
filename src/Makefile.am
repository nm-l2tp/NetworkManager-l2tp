INCLUDES = -I${top_srcdir}

AM_CPPFLAGS =							\
	$(GLIB_CFLAGS)                                  \
	$(LIBNM_CFLAGS)				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DNM_VERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\"				\
	-DNM_L2TP_LOCALEDIR=\"$(datadir)/locale\"		\
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" 

libexec_PROGRAMS = nm-l2tp-service

nm_l2tp_service_SOURCES = \
				nm-l2tp-service.c \
				nm-l2tp-service-defines.h \
				nm-l2tp-service.h

# D-Bus stuff
noinst_LTLIBRARIES = libnm-l2tp-pppd-service-dbus.la

nodist_libnm_l2tp_pppd_service_dbus_la_SOURCES = \
	nm-l2tp-pppd-service-dbus.c \
	nm-l2tp-pppd-service-dbus.h

libnm_l2tp_pppd_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nm-l2tp-pppd-service-dbus.h: $(top_srcdir)/src/nm-l2tp-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop \
		$<

nm-l2tp-pppd-service-dbus.c:
	@true

nm_l2tp_service_LDADD = 				\
				$(GLIB_LIBS)           \
				$(LIBNM_LIBS)		\
				libnm-l2tp-pppd-service-dbus.la

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-l2tp-pppd-plugin.la

nm_l2tp_pppd_plugin_la_SOURCES = \
	nm-l2tp-pppd-plugin.c \
	nm-ppp-status.h

nm_l2tp_pppd_plugin_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS)

nm_l2tp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_l2tp_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

BUILT_SOURCES = nm-l2tp-pppd-service-dbus.h nm-l2tp-pppd-service-dbus.c

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-l2tp-pppd-service.xml

