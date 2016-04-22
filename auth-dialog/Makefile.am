AM_CPPFLAGS = -I${top_srcdir}

libexec_PROGRAMS = nm-l2tp-auth-dialog

nm_l2tp_auth_dialog_CPPFLAGS =			\
	$(LIBNM_CFLAGS)				\
	$(GLIB_CFLAGS)				\
	$(GTK_CFLAGS)				\
	$(NMGTK_CFLAGS)				\
	$(LIBSECRET_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"			\
	-DBINDIR=\""$(bindir)"\"

nm_l2tp_auth_dialog_SOURCES =			\
	main.c

nm_l2tp_auth_dialog_LDADD =			\
	$(LIBNM_LIBS)				\
	$(GTK_LIBS)				\
	$(NMGTK_LIBS)				\
	$(LIBSECRET_LIBS)

CLEANFILES = *~
