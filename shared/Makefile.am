noinst_LTLIBRARIES = \
    libnm-vpn-plugin-l2tp-shared.la \
    libnm-vpn-editor-utils-shared.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-l2tp-shared.la
endif

shared_sources = \
    nm-utils/nm-shared-utils.c \
    nm-utils/nm-shared-utils.h \
    nm-service-defines.h

shared_CPPFLAGS = \
    -DLIBEXECDIR=\""$(libexecdir)"\" \
    -I"$(top_srcdir)/shared/"

###############################################################################

libnm_vpn_plugin_l2tp_shared_la_CPPFLAGS = \
    $(LIBNM_CFLAGS) \
    $(shared_CPPFLAGS)

libnm_vpn_plugin_l2tp_shared_la_SOURCES= \
    $(shared_sources)

libnm_vpn_plugin_l2tp_shared_la_LIBADD = \
    $(LIBNM_LIBS)

###############################################################################

libnm_l2tp_shared_la_SOURCES = \
    $(shared_sources)

libnm_l2tp_shared_la_CPPFLAGS = \
    -DNM_VPN_OLD \
    $(LIBNM_GLIB_CFLAGS) \
    $(shared_CPPFLAGS)

libnm_l2tp_shared_la_LIBADD = \
    $(LIBNM_GLIB_LIBS)

###############################################################################

libnm_vpn_editor_utils_shared_la_CPPFLAGS = \
    $(LIBNM_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_vpn_editor_utils_shared_la_SOURCES = \
    nm-vpn/nm-vpn-plugin-utils.c \
    nm-vpn/nm-vpn-plugin-utils.h

libnm_vpn_editor_utils_shared_la_LIBADD = \
    $(LIBNM_LIBS) \
    -ldl

###############################################################################

EXTRA_DIST = \
    nm-utils/gsystem-local-alloc.h \
    nm-utils/nm-glib.h \
    nm-utils/nm-macros-internal.h \
    nm-default.h

