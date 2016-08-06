plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-l2tp.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-l2tp-properties.la
endif

AM_CPPFLAGS = -I${top_srcdir}

plugin_sources = \
    nm-l2tp.c \
    nm-l2tp.h \
    ipsec-dialog.c \
    ipsec-dialog.h \
    advanced-dialog.c \
    advanced-dialog.h \
    import-export.c \
    import-export.h

uidir = $(datadir)/gnome-vpn-properties/l2tp
ui_DATA = nm-l2tp-dialog.ui

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    $(GTK_CFLAGS) \
    -I"$(top_srcdir)/shared" \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\""$(datadir)/locale"\"

###############################################################################

libnm_vpn_plugin_l2tp_la_SOURCES = \
    $(plugin_sources)

libnm_vpn_plugin_l2tp_la_CFLAGS = \
    $(common_CFLAGS) \
    $(LIBNMA_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_l2tp_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNMA_LIBS) \
    $(LIBNM_LIBS)

libnm_vpn_plugin_l2tp_la_LDFLAGS = \
    -avoid-version

###############################################################################

libnm_l2tp_properties_la_SOURCES = \
    $(plugin_sources)

libnm_l2tp_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    $(common_CFLAGS) \
    $(LIBNM_GLIB_CFLAGS) \
    $(LIBNM_GTK_CFLAGS)

libnm_l2tp_properties_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_GLIB_LIBS) \
    $(LIBNM_GTK_LIBS)

libnm_l2tp_properties_la_LDFLAGS = \
    -avoid-version

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
    $(ui_DATA)
