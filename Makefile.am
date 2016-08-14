AUTOMAKE_OPTIONS = foreign

SUBDIRS = shared properties src po

if WITH_GNOME
SUBDIRS += auth-dialog
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-l2tp-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-l2tp-service.name

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-l2tp-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-l2tp-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-l2tp-service.name
endif

appdatadir = $(datadir)/appdata
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-l2tp.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-l2tp-service.name: $(srcdir)/nm-l2tp-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

EXTRA_DIST = nm-l2tp-service.name.in \
             $(dbusservice_DATA)  \
             $(appdata_in_files)  \
             $(appdata_files)      \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) \
             $(appdata_files)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
