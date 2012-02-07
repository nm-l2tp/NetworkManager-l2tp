plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-l2tp-properties.la

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
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        $(GNOMEKEYRING_CFLAGS)                          \
        $(NM_CFLAGS)                              \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\" 								\
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"          \
        -DVERSION=\"$(VERSION)\"

libnm_l2tp_properties_la_LIBADD =    \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)              \
        $(top_builddir)/common-gnome/libnm-l2tp-common-gnome.la	\
        $(NM_LIBS)

libnm_l2tp_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
