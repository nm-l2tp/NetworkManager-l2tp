plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-l2tp-properties.la

INCLUDES = -I${top_srcdir}

libnm_l2tp_properties_la_SOURCES = \
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

libnm_l2tp_properties_la_CFLAGS =                    \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                                    \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\""$(datadir)/locale"\"             \
        -DG_DISABLE_DEPRECATED                          \
        -DVERSION=\"$(VERSION)\"

libnm_l2tp_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS)

libnm_l2tp_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
