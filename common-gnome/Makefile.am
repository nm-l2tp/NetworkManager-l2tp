noinst_LTLIBRARIES=libnm-l2tp-common-gnome.la

libnm_l2tp_common_gnome_la_CPPFLAGS = \
	$(NM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_l2tp_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_l2tp_common_gnome_la_LIBADD = \
	$(NM_LIBS) \
	$(GLIB_LIBS) \
	$(GNOMEKEYRING_LIBS)

