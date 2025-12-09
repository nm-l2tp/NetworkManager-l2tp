/* SPDX-License-Identifier: GPL-2.0-or-later */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
 *
 */

#include "nm-default.h"

#include "nm-l2tp-editor-plugin.h"
#include "nm-utils/nm-vpn-plugin-utils.h"

#include "import-export.h"

#define L2TP_PLUGIN_NAME _("Layer 2 Tunneling Protocol (L2TP)")
#define L2TP_PLUGIN_DESC _("Compatible with Microsoft and other L2TP VPN servers.")

/*****************************************************************************/

static void l2tp_plugin_ui_interface_init(NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED(L2tpPluginUi,
                       l2tp_plugin_ui,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN,
                                             l2tp_plugin_ui_interface_init))

enum {
    PROP_0,
    PROP_NAME,
    PROP_DESC,
    PROP_SERVICE,

    LAST_PROP
};

/*****************************************************************************/

static NMConnection *
import(NMVpnEditorPlugin *iface, const char *path, GError **error)
{
    NMConnection *connection = NULL;
    char *        ext;

    ext = strrchr(path, '.');
    if (!ext) {
        g_set_error(error,
                    NMV_EDITOR_PLUGIN_ERROR,
                    NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN,
                    "unknown L2TP file extension");
        return NULL;
    }

    if (strcmp(ext, ".conf") && strcmp(ext, ".cnf")) {
        g_set_error(error,
                    NMV_EDITOR_PLUGIN_ERROR,
                    NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN,
                    "unknown L2TP file extension");
        return NULL;
    }

    connection = do_import(path, error);

    return connection;
}

static gboolean export(NMVpnEditorPlugin *iface,
                       const char *       path,
                       NMConnection *     connection,
                       GError **          error)
{
    return do_export(path, connection, error);
}

static char *
get_suggested_filename(NMVpnEditorPlugin *iface, NMConnection *connection)
{
    NMSettingConnection *s_con;
    const char *         id;

    g_return_val_if_fail(connection != NULL, NULL);

    s_con = nm_connection_get_setting_connection(connection);
    g_return_val_if_fail(s_con != NULL, NULL);

    id = nm_setting_connection_get_id(s_con);
    g_return_val_if_fail(id != NULL, NULL);

    return g_strdup_printf("%s (l2tp).conf", id);
}

#if !NM_CHECK_VERSION(1, 52, 0)
#define NM_VPN_EDITOR_PLUGIN_CAPABILITY_NO_EDITOR 0x08
#endif

static NMVpnEditorPluginCapability
get_capabilities(NMVpnEditorPlugin *iface)
{
    NMVpnEditorPluginCapability capabilities;

    capabilities = NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT;
    capabilities |= NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT;
    if (L2TP_PLUGIN_UI(iface)->module_path == NULL)
            capabilities |= NM_VPN_EDITOR_PLUGIN_CAPABILITY_NO_EDITOR;
    return capabilities;

}

static NMVpnEditor *
_call_editor_factory(gpointer           factory,
                     NMVpnEditorPlugin *editor_plugin,
                     NMConnection *     connection,
                     gpointer           user_data,
                     GError **          error)
{
    return ((NMVpnEditorFactory) factory)(editor_plugin, connection, error);
}

static NMVpnEditor *
get_editor(NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
    return nm_vpn_plugin_utils_load_editor(L2TP_PLUGIN_UI(iface)->module_path,
                                           "nm_vpn_editor_factory_l2tp",
                                           _call_editor_factory,
                                           iface,
                                           connection,
                                           NULL,
                                           error);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    switch (prop_id) {
    case PROP_NAME:
        g_value_set_string(value, L2TP_PLUGIN_NAME);
        break;
    case PROP_DESC:
        g_value_set_string(value, L2TP_PLUGIN_DESC);
        break;
    case PROP_SERVICE:
        g_value_set_string(value, NM_DBUS_SERVICE_L2TP);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
dispose (GObject *object)
{
    L2tpPluginUi *editor_plugin = L2TP_PLUGIN_UI(object);

    g_clear_pointer (&editor_plugin->module_path, g_free);

    G_OBJECT_CLASS (l2tp_plugin_ui_parent_class)->dispose (object);
}

static void
l2tp_plugin_ui_class_init(L2tpPluginUiClass *req_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(req_class);

    object_class->get_property = get_property;
    object_class->dispose = dispose;

    g_object_class_override_property(object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);

    g_object_class_override_property(object_class, PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

    g_object_class_override_property(object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
l2tp_plugin_ui_init(L2tpPluginUi *plugin)
{}

static void
l2tp_plugin_ui_interface_init(NMVpnEditorPluginInterface *iface_class)
{
    iface_class->get_editor             = get_editor;
    iface_class->get_capabilities       = get_capabilities;
    iface_class->import_from_file       = import;
    iface_class->export_to_file         = export;
    iface_class->get_suggested_filename = get_suggested_filename;
}

/*****************************************************************************/

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    L2tpPluginUi *editor_plugin;
    gpointer gtk3_only_symbol;
    GModule *self_module;

    g_return_val_if_fail (!error || !*error, NULL);

    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");

    self_module = g_module_open (NULL, 0);
    g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
    g_module_close (self_module);

    editor_plugin = g_object_new (L2TP_TYPE_PLUGIN_UI, NULL);
    editor_plugin->module_path = nm_vpn_plugin_utils_get_editor_module_path
            (gtk3_only_symbol ?
             "libnm-vpn-plugin-l2tp-editor.so" :
             "libnm-gtk4-vpn-plugin-l2tp-editor.so",
             NULL);

    return NM_VPN_EDITOR_PLUGIN(editor_plugin);
}
