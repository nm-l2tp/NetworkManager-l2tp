AM_CPPFLAGS = -I${top_srcdir}

libexec_PROGRAMS = nm-l2tp-auth-dialog

nm_l2tp_auth_dialog_CPPFLAGS =			\
	$(NM_CFLAGS)		\
	$(GLIB_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(NMGTK_CFLAGS)				\
	$(LIBSECRET_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"			\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DVERSION=\"$(VERSION)\"

if HAVE_NM_VPN_PASSWORD_DIALOG_H
nm_l2tp_auth_dialog_SOURCES = main.c
else
nm_l2tp_auth_dialog_SOURCES = main.c vpn-password-dialog.c vpn-password-dialog.h
endif

nm_l2tp_auth_dialog_LDADD =			\
	$(NM_LIBS) \
	$(GTK_LIBS) \
	$(NMGTK_LIBS) \
	$(LIBSECRET_LIBS)

CLEANFILES = *~
