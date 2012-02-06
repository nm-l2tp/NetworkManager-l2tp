INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-l2tp-auth-dialog

nm_l2tp_auth_dialog_CPPFLAGS =			\
	$(NM_CFLAGS)			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(GCONF_CFLAGS)				\
	$(GNOMEKEYRING_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DGLADEDIR=\""$(gladedir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"

nm_l2tp_auth_dialog_SOURCES =			\
	main.c					\
	gnome-two-password-dialog.c		\
	gnome-two-password-dialog.h

nm_l2tp_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(GCONF_LIBS)				\
	$(top_builddir)/common-gnome/libnm-l2tp-common-gnome.la

CLEANFILES = *~
