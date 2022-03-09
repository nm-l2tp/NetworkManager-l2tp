AUTOMAKE_OPTIONS = subdir-objects

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes

libexec_PROGRAMS =

noinst_LTLIBRARIES =

EXTRA_DIST =

CLEANFILES =

noinst_PROGRAMS =

SUBDIRS = \
	. \
	po

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-l2tp-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-l2tp-service.name

BUILT_SOURCES =

###############################################################################

shared_sources = \
	shared/nm-default.h \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h

EXTRA_DIST += \
	README.md \
	autogen.sh \
	shared/README

src_cppflags = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I$(builddir)/src \
	-DNM_L2TP_LOCALEDIR=\"$(datadir)/locale\" \
	-DNM_L2TP_STATEDIR=\"$(l2tp_statedir)\" \
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" \
	-DRUNSTATEDIR=\"$(runstatedir)\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT

###############################################################################

noinst_LTLIBRARIES += src/libnm-l2tp-pppd-service-dbus.la

nodist_src_libnm_l2tp_pppd_service_dbus_la_SOURCES = \
	src/nm-l2tp-pppd-service-dbus.c \
	src/nm-l2tp-pppd-service-dbus.h

src_libnm_l2tp_pppd_service_dbus_la_CPPFLAGS = \
	$(src_cppflags) \
	$(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

src/nm-l2tp-pppd-service-dbus.h: $(top_srcdir)/src/nm-l2tp-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

src/nm-l2tp-pppd-service-dbus.c: src/nm-l2tp-pppd-service-dbus.h
	@true

BUILT_SOURCES += \
	src/nm-l2tp-pppd-service-dbus.h \
	src/nm-l2tp-pppd-service-dbus.c

CLEANFILES += \
	src/nm-l2tp-pppd-service-dbus.h \
	src/nm-l2tp-pppd-service-dbus.c

EXTRA_DIST += \
	src/nm-l2tp-pppd-service.xml

###############################################################################

libexec_PROGRAMS += src/nm-l2tp-service

src_nm_l2tp_service_SOURCES = \
	$(shared_sources) \
	shared/nm-service-defines.h \
	shared/nm-l2tp-crypto-openssl.h \
	shared/nm-l2tp-crypto-openssl.c \
	shared/nm-l2tp-crypto-nss.h \
	shared/nm-l2tp-crypto-nss.c \
	shared/utils.h \
	shared/utils.c \
	src/nm-ppp-status.h \
	src/nm-l2tp-service.h \
	src/nm-l2tp-service.c
src_nm_l2tp_service_CPPFLAGS = $(src_cppflags) $(NSS_CFLAGS) $(OPENSSL_CFLAGS)
src_nm_l2tp_service_LDADD = \
	src/libnm-l2tp-pppd-service-dbus.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(OPENSSL_LIBS) \
	$(NSS_LIBS)

###############################################################################

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = src/nm-l2tp-pppd-plugin.la

src_nm_l2tp_pppd_plugin_la_SOURCES = \
	$(shared_sources) \
	src/nm-l2tp-pppd-plugin.c \
	src/nm-ppp-status.h
src_nm_l2tp_pppd_plugin_la_CPPFLAGS = $(src_cppflags)
src_nm_l2tp_pppd_plugin_la_LDFLAGS = \
	-module -avoid-version
src_nm_l2tp_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

gtk4/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/properties/gresource.xml |sed "s,^,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(builddir)/gtk4 --generate-source --internal

gtk4/%.ui: properties/%.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< |grep -v can-default >$@

plugin_sources = \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	shared/nm-l2tp-crypto-openssl.c \
	shared/nm-l2tp-crypto-openssl.h \
	properties/nm-l2tp-editor-plugin.c \
	properties/nm-l2tp-editor-plugin.h \
	properties/import-export.c \
	properties/import-export.h

editor_sources = \
	$(shared_sources) \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-l2tp-crypto-openssl.c \
	shared/nm-l2tp-crypto-openssl.h \
	shared/utils.h \
	shared/utils.c \
	properties/ppp-dialog.c \
	properties/ppp-dialog.h \
	properties/ipsec-dialog.c \
	properties/ipsec-dialog.h \
	properties/nm-l2tp-editor.c \
	properties/nm-l2tp-editor.h \
	properties/auth-helpers.c \
	properties/auth-helpers.h

properties_cppflags = \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)/shared \
	$(OPENSSL_CFLAGS)

CLEANFILES += \
	properties/resources.c \
	properties/resources.h \
	gtk4/resources.c \
	gtk4/nm-l2tp-dialog.ui

EXTRA_DIST += \
	properties/nm-l2tp-dialog.ui \
	properties/gresource.xml \
	properties/libnm-l2tp-properties.ver \
	properties/libnm-vpn-plugin-l2tp.ver \
	properties/libnm-vpn-plugin-l2tp-editor.ver

###############################################################################

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-l2tp.la

properties_libnm_vpn_plugin_l2tp_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	$(plugin_sources)
properties_libnm_vpn_plugin_l2tp_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(OPENSSL_CFLAGS)
properties_libnm_vpn_plugin_l2tp_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	$(properties_cppflags)
properties_libnm_vpn_plugin_l2tp_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(OPENSSL_LIBS)
properties_libnm_vpn_plugin_l2tp_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-l2tp.ver"

###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-l2tp-editor.la
endif

properties_libnm_vpn_plugin_l2tp_editor_la_SOURCES = \
	$(editor_sources)
nodist_properties_libnm_vpn_plugin_l2tp_editor_la_SOURCES = \
	properties/resources.c \
	properties/resources.h
properties_libnm_vpn_plugin_l2tp_editor_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(OPENSSL_CFLAGS)
properties_libnm_vpn_plugin_l2tp_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags)
properties_libnm_vpn_plugin_l2tp_editor_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(OPENSSL_LIBS)
properties_libnm_vpn_plugin_l2tp_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-l2tp-editor.ver"

###############################################################################

if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-l2tp-editor.la
endif

properties_libnm_gtk4_vpn_plugin_l2tp_editor_la_SOURCES = \
	$(editor_sources)
nodist_properties_libnm_gtk4_vpn_plugin_l2tp_editor_la_SOURCES = \
	gtk4/resources.c \
	properties/resources.h
properties_libnm_gtk4_vpn_plugin_l2tp_editor_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS) \
	$(OPENSSL_CFLAGS)
properties_libnm_gtk4_vpn_plugin_l2tp_editor_la_CPPFLAGS = \
	$(properties_libnm_vpn_plugin_l2tp_editor_la_CPPFLAGS)
properties_libnm_gtk4_vpn_plugin_l2tp_editor_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS) \
	$(OPENSSL_LIBS)
properties_libnm_gtk4_vpn_plugin_l2tp_editor_la_LDFLAGS = \
	$(properties_libnm_vpn_plugin_l2tp_editor_la_LDFLAGS)

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-l2tp-auth-dialog
endif

auth_dialog_nm_l2tp_auth_dialog_SOURCES = \
	$(shared_sources) \
	shared/nm-l2tp-crypto-openssl.c \
	shared/nm-l2tp-crypto-openssl.h \
	shared/nm-utils/nm-secret-utils.c \
	shared/nm-utils/nm-secret-utils.h \
	auth-dialog/main.c
auth_dialog_nm_l2tp_auth_dialog_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	$(OPENSSL_CFLAGS)
auth_dialog_nm_l2tp_auth_dialog_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	-I$(top_srcdir)/shared
auth_dialog_nm_l2tp_auth_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS) \
	$(OPENSSL_LIBS)

###############################################################################

appdatadir = $(datadir)/metainfo
appdata_in_files = appdata/network-manager-l2tp.metainfo.xml.in
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)

$(appdata_DATA): $(appdata_in_files)
	$(AM_V_GEN)$(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@
endif

nm-l2tp-service.name: $(srcdir)/nm-l2tp-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

EXTRA_DIST += \
	nm-l2tp-service.name.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files)

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

ACLOCAL_AMFLAGS = -I m4
