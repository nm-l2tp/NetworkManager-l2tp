INCLUDES = -I${top_srcdir}

AM_CPPFLAGS =							\
	$(DBUS_GLIB_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(NM_CFLAGS)				\
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
				nm-l2tp-service.h

nm-l2tp-pppd-service-glue.h: $(top_srcdir)/src/nm-l2tp-pppd-service.xml
	dbus-binding-tool --prefix=nm_l2tp_pppd_service --mode=glib-server --output=$@ $<

nm_l2tp_service_LDADD = 				\
				$(DBUS_GLIB_LIBS)		\
				$(GTHREAD_LIBS)		\
				$(NM_LIBS)

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-l2tp-pppd-plugin.la

nm_l2tp_pppd_plugin_la_SOURCES = \
	nm-l2tp-pppd-plugin.c \
	nm-ppp-status.h

nm_l2tp_pppd_plugin_la_CPPFLAGS = \
	$(DBUS_GLIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(NM_CFLAGS)

nm_l2tp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_l2tp_pppd_plugin_la_LIBADD = \
	$(DBUS_GLIB_LIBS) \
	$(GLIB_LIBS) \
	$(NM_LIBS)

BUILT_SOURCES = nm-l2tp-pppd-service-glue.h

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-l2tp-pppd-service.xml

