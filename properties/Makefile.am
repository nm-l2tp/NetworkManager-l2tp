plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-l2tp.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-l2tp-properties.la
endif

INCLUDES = -I${top_srcdir}

libnm_vpn_plugin_l2tp_la_SOURCES = \
	nm-l2tp.c \
	nm-l2tp.h \
	ipsec-dialog.c \
	ipsec-dialog.h \
	advanced-dialog.c \
	advanced-dialog.h \
	import-export.c \
	import-export.h

libnm_l2tp_properties_la_SOURCES = \
        $(libnm_vpn_plugin_l2tp_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/l2tp
ui_DATA = nm-l2tp-dialog.ui

common_CFLAGS =                                         \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\""$(datadir)/locale"\"

libnm_vpn_plugin_l2tp_la_CFLAGS =                       \
        $(LIBNM_CFLAGS)                                 \
        $(common_CFLAGS)

libnm_l2tp_properties_la_CFLAGS =                       \
        -DNM_L2TP_OLD                                   \
        $(LIBNM_GLIB_CFLAGS)                            \
        $(common_CFLAGS)

libnm_vpn_plugin_l2tp_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_LIBS)

libnm_l2tp_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_GLIB_LIBS)

libnm_vpn_plugin_l2tp_la_LDFLAGS =   \
        -avoid-version

libnm_l2tp_properties_la_LDFLAGS =   \
        $(libnm_vpn_plugin_l2tp_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
