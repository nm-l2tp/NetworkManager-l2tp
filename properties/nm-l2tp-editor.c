/* SPDX-License-Identifier: GPL-2.0-or-later */
/***************************************************************************
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
 *
 */

#include "nm-default.h"

#include "nm-l2tp-editor.h"

#include <ctype.h>
#include <gtk/gtk.h>

#include "ppp-dialog.h"
#include "ipsec-dialog.h"

#include "shared/utils.h"
#include "shared/nm-l2tp-crypto-openssl.h"

#include "auth-helpers.h"

#include "nm-l2tp-editor-plugin.h"

/*****************************************************************************/

static void l2tp_plugin_ui_widget_interface_init(NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED(L2tpPluginUiWidget,
                       l2tp_plugin_ui_widget,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR,
                                             l2tp_plugin_ui_widget_interface_init))

#define L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), L2TP_TYPE_PLUGIN_UI_WIDGET, L2tpPluginUiWidgetPrivate))

typedef void (*ChangedCallback)(GtkWidget *widget, gpointer user_data);

typedef struct {
    GtkBuilder *    builder;
    GtkWidget *     widget;
    GtkWindowGroup *window_group;
    gboolean        window_added;
    GHashTable *    ppp;
    GHashTable *    ipsec;
    gboolean        new_connection;
} L2tpPluginUiWidgetPrivate;

/**
 * Return copy of string #s with the leading and trailing spaces removed
 * result must be freed with g_free()
 **/
static char *
strstrip(const char *s)
{
    size_t size;
    char * end;
    char * scpy;

    /* leading */
    while (*s && isspace(*s))
        s++;

    scpy = g_strdup(s);
    size = strlen(scpy);

    if (!size)
        return scpy;

    end = scpy + size - 1;

    while (end >= scpy && isspace(*end))
        end--;
    *(end + 1) = '\0';

    return scpy;
}

static void
tls_cert_changed_cb(GtkWidget *chooser, gpointer user_data)
{
    GtkFileChooser *this = GTK_FILE_CHOOSER(chooser);
    GtkFileChooser *       ca_cert, *cert, *key;
    GtkBuilder *           builder = (GtkBuilder *) user_data;
    GtkWidget *            widget;
    char *                 fname, *dirname, *ca_cert_fname, *cert_fname, *key_fname;
    NML2tpCryptoFileFormat tls_fileformat = NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN;
    gboolean               tls_need_password;
    gboolean               sensitive_ca_key = TRUE;
    GError *               config_error     = NULL;
    gulong                 id, id1, id2, id3;
    guint32                i                          = 0;
    const char *           sensitive_ca_key_widgets[] = {"user_ca_certificate_label",
                                              "user_tls_ca_cert_chooser",
                                              "user_private_key_label",
                                              "user_tls_private_key_chooser",
                                              NULL};

    /**
     * If the just-changed file chooser is a PKCS#12 file, then all of the
     * TLS filechoosers have to be PKCS#12.  But if it just changed to something
     * other than a PKCS#12 file, then clear out the other file choosers.
     *
     * Basically, all the choosers have to contain PKCS#12 files, or none of
     * them can, because PKCS#12 files contain everything required for the TLS
     * connection (CA cert, cert, private key).
     **/

    crypto_init_openssl();

    fname = gtk_file_chooser_get_filename(this);
    if (fname)
        dirname = g_path_get_dirname(fname);
    else
        dirname = NULL;

    ca_cert = GTK_FILE_CHOOSER(gtk_builder_get_object(builder, "user_tls_ca_cert_chooser"));
    cert    = GTK_FILE_CHOOSER(gtk_builder_get_object(builder, "user_tls_cert_chooser"));
    key     = GTK_FILE_CHOOSER(gtk_builder_get_object(builder, "user_tls_private_key_chooser"));

    ca_cert_fname = gtk_file_chooser_get_filename(ca_cert);
    cert_fname    = gtk_file_chooser_get_filename(cert);
    key_fname     = gtk_file_chooser_get_filename(key);

    id  = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(this), BLOCK_HANDLER_ID));
    id1 = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(ca_cert), BLOCK_HANDLER_ID));
    id2 = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(cert), BLOCK_HANDLER_ID));
    id3 = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(key), BLOCK_HANDLER_ID));

    g_signal_handler_block(ca_cert, id1);
    g_signal_handler_block(cert, id2);
    g_signal_handler_block(key, id3);

    tls_fileformat = crypto_file_format(fname, &tls_need_password, &config_error);
    if (!ca_cert_fname && !cert_fname && !key_fname) {
        sensitive_ca_key = FALSE;

    } else if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
        /* Make sure all choosers have this PKCS#12 file */
        if (!nm_streq0(fname, ca_cert_fname))
            gtk_file_chooser_set_filename(ca_cert, fname);
        if (!nm_streq0(fname, cert_fname))
            gtk_file_chooser_set_filename(cert, fname);
        if (!nm_streq0(fname, key_fname))
            gtk_file_chooser_set_filename(key, fname);

        sensitive_ca_key = FALSE;

    } else {
        /**
         * Just-chosen file isn't PKCS#12 or no file was chosen, so clear out other
         * file selectors that have PKCS#12 files in them.
         * Set directory of unset file choosers to the directory just selected.
         */
        if (id != id1) {
            tls_fileformat = crypto_file_format(ca_cert_fname, NULL, &config_error);
            if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
                gtk_file_chooser_unselect_all(ca_cert);

                if (!ca_cert_fname && dirname)
                    gtk_file_chooser_set_current_folder(ca_cert, dirname);
            }
        }
        if (id != id2) {
            tls_fileformat = crypto_file_format(cert_fname, NULL, &config_error);
            if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
                gtk_file_chooser_unselect_all(cert);

                if (!cert_fname && dirname)
                    gtk_file_chooser_set_current_folder(cert, dirname);
            }
        }
        tls_fileformat = crypto_file_format(key_fname, &tls_need_password, &config_error);
        if (id != id3) {
            if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
                gtk_file_chooser_unselect_all(key);

                if (!key_fname && dirname)
                    gtk_file_chooser_set_current_folder(key, dirname);
            }
        }
    }

    g_signal_handler_unblock(ca_cert, id1);
    g_signal_handler_unblock(cert, id2);
    g_signal_handler_unblock(key, id3);

    g_free(fname);
    g_free(dirname);
    g_free(ca_cert_fname);
    g_free(cert_fname);
    g_free(key_fname);
    crypto_deinit_openssl();

    while (sensitive_ca_key_widgets[i]) {
        widget = GTK_WIDGET(gtk_builder_get_object(builder, sensitive_ca_key_widgets[i++]));
        gtk_widget_set_sensitive(widget, sensitive_ca_key);
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "user_tls_key_pw_entry"));
    if (!tls_need_password) {
        gtk_entry_set_visibility(GTK_ENTRY(widget), FALSE);
        if (gtk_entry_get_text(GTK_ENTRY(widget)))
            gtk_entry_set_text(GTK_ENTRY(widget), "");
    }
    gtk_widget_set_sensitive(widget, tls_need_password);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "show_user_tls_key_pw_check"));
    if (!tls_need_password) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), tls_need_password);
    }
    gtk_widget_set_sensitive(widget, tls_need_password);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "user_key_pw_label"));
    gtk_widget_set_sensitive(widget, tls_need_password);
}

static void
pw_setup(GtkBuilder *builder, NMSettingVpn *s_vpn, ChangedCallback changed_cb, gpointer user_data)
{
    GtkWidget * widget, *show_password;
    const char *value;

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "username_entry"));
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_USER);
        if (value && value[0])
            gtk_entry_set_text(GTK_ENTRY(widget), value);
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(changed_cb), user_data);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "domain_entry"));
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_DOMAIN);
        if (value && value[0])
            gtk_entry_set_text(GTK_ENTRY(widget), value);
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(changed_cb), user_data);

    /* Fill in the user password */
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "password_entry"));
    if (s_vpn) {
        value = nm_setting_vpn_get_secret(s_vpn, NM_L2TP_KEY_PASSWORD);
        if (value)
            gtk_entry_set_text(GTK_ENTRY(widget), value);
    }
    g_signal_connect(widget, "changed", G_CALLBACK(changed_cb), user_data);
    nma_utils_setup_password_storage(widget,
                                     0,
                                     (NMSetting *) s_vpn,
                                     NM_L2TP_KEY_PASSWORD,
                                     FALSE,
                                     FALSE);

    show_password = GTK_WIDGET(gtk_builder_get_object(builder, "show_password_checkbutton"));
    g_signal_connect(show_password, "toggled", G_CALLBACK(show_password_cb), widget);
}

static void
update_from_filechooser(GtkBuilder *  builder,
                        const char *  key,
                        const char *  widget_name,
                        NMSettingVpn *s_vpn)
{
    GtkWidget *widget;
    char *     filename;

    g_return_if_fail(builder != NULL);
    g_return_if_fail(key != NULL);
    g_return_if_fail(widget_name != NULL);
    g_return_if_fail(s_vpn != NULL);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, widget_name));

    filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(widget));
    if (filename && filename[0])
        nm_setting_vpn_add_data_item(s_vpn, key, filename);
    g_free(filename);
}

static void
update_tls(GtkBuilder *builder, NMSettingVpn *s_vpn)
{
    GtkWidget *          widget;
    NMSettingSecretFlags pw_flags;
    const char *         str;

    g_return_if_fail(builder != NULL);
    g_return_if_fail(s_vpn != NULL);

    update_from_filechooser(builder, NM_L2TP_KEY_USER_CA, "user_tls_ca_cert_chooser", s_vpn);
    update_from_filechooser(builder, NM_L2TP_KEY_USER_CERT, "user_tls_cert_chooser", s_vpn);
    update_from_filechooser(builder, NM_L2TP_KEY_USER_KEY, "user_tls_private_key_chooser", s_vpn);

    /* Password */
    widget = (GtkWidget *) gtk_builder_get_object(builder, "user_tls_key_pw_entry");
    str    = gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && str[0])
        nm_setting_vpn_add_secret(s_vpn, NM_L2TP_KEY_USER_CERTPASS, str);
    pw_flags = nma_utils_menu_to_secret_flags(widget);
    nm_setting_set_secret_flags(NM_SETTING(s_vpn), NM_L2TP_KEY_USER_CERTPASS, pw_flags, NULL);
}

static void
update_pw(GtkBuilder *builder, NMSettingVpn *s_vpn)
{
    GtkWidget *          widget;
    NMSettingSecretFlags pw_flags;
    const char *         str;

    g_return_if_fail(builder != NULL);
    g_return_if_fail(s_vpn != NULL);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "username_entry"));
    str    = gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && str[0])
        nm_setting_vpn_add_data_item(s_vpn, NM_L2TP_KEY_USER, str);

    widget = (GtkWidget *) gtk_builder_get_object(builder, "password_entry");
    str    = gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && str[0])
        nm_setting_vpn_add_secret(s_vpn, NM_L2TP_KEY_PASSWORD, str);
    pw_flags = nma_utils_menu_to_secret_flags(widget);
    nm_setting_set_secret_flags(NM_SETTING(s_vpn), NM_L2TP_KEY_PASSWORD, pw_flags, NULL);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "domain_entry"));
    str    = gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && str[0])
        nm_setting_vpn_add_data_item(s_vpn, NM_L2TP_KEY_DOMAIN, str);
}

static gboolean
check_validity(L2tpPluginUiWidget *self, GError **error)
{
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GtkWidget *                widget;
    const char *               str;
    char *                     s = NULL;

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "gateway_entry"));
    str    = gtk_entry_get_text(GTK_ENTRY(widget));
    if (!str || !strlen(s = strstrip(str))) {
        g_free(s);
        g_set_error(error,
                    NMV_EDITOR_PLUGIN_ERROR,
                    NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
                    NM_L2TP_KEY_GATEWAY);
        return FALSE;
    }

    return TRUE;
}

static void
stuff_changed_cb(GtkWidget *widget, gpointer user_data)
{
    g_signal_emit_by_name(L2TP_PLUGIN_UI_WIDGET(user_data), "changed");
}

static void
auth_combo_changed_cb(GtkWidget *combo, gpointer user_data)
{
    L2tpPluginUiWidget *       self = L2TP_PLUGIN_UI_WIDGET(user_data);
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GtkWidget *                auth_notebook;
    GtkTreeModel *             model;
    GtkTreeIter                iter;
    gint                       new_page = 0;

    model = gtk_combo_box_get_model(GTK_COMBO_BOX(combo));
    g_assert(gtk_combo_box_get_active_iter(GTK_COMBO_BOX(combo), &iter));
    gtk_tree_model_get(model, &iter, COL_AUTH_PAGE, &new_page, -1);

    auth_notebook = GTK_WIDGET(gtk_builder_get_object(priv->builder, "auth_notebook"));
    gtk_notebook_set_current_page(GTK_NOTEBOOK(auth_notebook), new_page);

    stuff_changed_cb(combo, self);
}

static void
ppp_dialog_close_cb(GtkWidget *dialog, gpointer user_data)
{
    gtk_widget_hide(dialog);
    /* gtk_widget_destroy() will remove the window from the window group */
    gtk_widget_destroy(dialog);
}

static void
ipsec_dialog_close_cb(GtkWidget *dialog, gpointer user_data)
{
    gtk_widget_hide(dialog);
    /* gtk_widget_destroy() will remove the window from the window group */
    gtk_widget_destroy(dialog);
}

static void
ppp_dialog_response_cb(GtkWidget *dialog, gint response, gpointer user_data)
{
    L2tpPluginUiWidget *       self  = L2TP_PLUGIN_UI_WIDGET(user_data);
    L2tpPluginUiWidgetPrivate *priv  = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GError *                   error = NULL;

    if (response != GTK_RESPONSE_OK) {
        ppp_dialog_close_cb(dialog, self);
        return;
    }

    if (priv->ppp)
        g_hash_table_destroy(priv->ppp);
    priv->ppp = ppp_dialog_new_hash_from_dialog(dialog, &error);
    if (!priv->ppp) {
        g_message(_("%s: error reading ppp settings: %s"), __func__, error->message);
        g_error_free(error);
    }
    ppp_dialog_close_cb(dialog, self);

    stuff_changed_cb(NULL, self);
}

static void
ipsec_dialog_response_cb(GtkWidget *dialog, gint response, gpointer user_data)
{
    L2tpPluginUiWidget *       self  = L2TP_PLUGIN_UI_WIDGET(user_data);
    L2tpPluginUiWidgetPrivate *priv  = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GError *                   error = NULL;

    if (response != GTK_RESPONSE_OK) {
        ipsec_dialog_close_cb(dialog, self);
        return;
    }

    if (priv->ipsec)
        g_hash_table_destroy(priv->ipsec);
    priv->ipsec = ipsec_dialog_new_hash_from_dialog(dialog, &error);
    if (!priv->ipsec) {
        g_message(_("%s: error reading ipsec settings: %s"), __func__, error->message);
        g_error_free(error);
    }
    ipsec_dialog_close_cb(dialog, self);

    stuff_changed_cb(NULL, self);
}

static void
ppp_button_clicked_cb(GtkWidget *button, gpointer user_data)
{
    L2tpPluginUiWidget *       self = L2TP_PLUGIN_UI_WIDGET(user_data);
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GtkWidget *                dialog, *toplevel, *widget;
    GtkBuilder *               builder;
    GtkTreeModel *             model;
    GtkTreeIter                iter;
    const char *               authtype = NULL;
    gboolean                   success;
    guint32                    i = 0;
    const char *widgets[] = {"ppp_auth_label", "auth_methods_label", "ppp_auth_methods", NULL};
    toplevel              = gtk_widget_get_toplevel(priv->widget);
    g_return_if_fail(gtk_widget_is_toplevel(toplevel));

    widget  = GTK_WIDGET(gtk_builder_get_object(priv->builder, "auth_combo"));
    model   = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
    success = gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget), &iter);
    g_return_if_fail(success == TRUE);
    gtk_tree_model_get(model, &iter, COL_AUTH_TYPE, &authtype, -1);

    dialog = ppp_dialog_new(priv->ppp, authtype);
    if (!dialog) {
        g_warning(_("%s: failed to create the PPP dialog!"), __func__);
        return;
    }

    gtk_window_group_add_window(priv->window_group, GTK_WINDOW(dialog));
    if (!priv->window_added) {
        gtk_window_group_add_window(priv->window_group, GTK_WINDOW(toplevel));
        priv->window_added = TRUE;
    }

    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(toplevel));
    g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(ppp_dialog_response_cb), self);
    g_signal_connect(G_OBJECT(dialog), "close", G_CALLBACK(ppp_dialog_close_cb), self);

    builder = g_object_get_data(G_OBJECT(dialog), "gtkbuilder-xml");
    g_return_if_fail(builder != NULL);

    if (authtype) {
        if (strcmp(authtype, NM_L2TP_AUTHTYPE_TLS) == 0) {
            while (widgets[i]) {
                widget = GTK_WIDGET(gtk_builder_get_object(builder, widgets[i++]));
                gtk_widget_set_sensitive(widget, FALSE);
            }
        }
    }

    gtk_widget_show_all(dialog);
}

static void
ipsec_button_clicked_cb(GtkWidget *button, gpointer user_data)
{
    L2tpPluginUiWidget *       self = L2TP_PLUGIN_UI_WIDGET(user_data);
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GtkWidget *                dialog, *toplevel, *widget;
    GtkBuilder *               builder;
    const char *               authtype = NULL;

    toplevel = gtk_widget_get_toplevel(priv->widget);
    g_return_if_fail(gtk_widget_is_toplevel(toplevel));

    dialog = ipsec_dialog_new(priv->ipsec);
    if (!dialog) {
        g_warning(_("%s: failed to create the IPsec dialog!"), __func__);
        return;
    }

    gtk_window_group_add_window(priv->window_group, GTK_WINDOW(dialog));
    if (!priv->window_added) {
        gtk_window_group_add_window(priv->window_group, GTK_WINDOW(toplevel));
        priv->window_added = TRUE;
    }

    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(toplevel));
    g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(ipsec_dialog_response_cb), self);
    g_signal_connect(G_OBJECT(dialog), "close", G_CALLBACK(ipsec_dialog_close_cb), self);

    gtk_widget_show_all(dialog);

    authtype = g_object_get_data(G_OBJECT(dialog), "auth-type");
    if (authtype) {
        if (strcmp(authtype, NM_L2TP_AUTHTYPE_TLS) != 0) {
            builder = g_object_get_data(G_OBJECT(dialog), "gtkbuilder-xml");
            widget  = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_tls_vbox"));
            gtk_widget_hide(widget);
        }
    }
}

static void
tls_setup(GtkBuilder *builder, NMSettingVpn *s_vpn, gpointer user_data)
{
    GtkWidget *    widget;
    GtkWidget *    show_password;
    GtkWidget *    ca_cert;
    GtkWidget *    cert;
    GtkWidget *    key;
    const char *   value;
    GtkFileFilter *filter;
    gulong         id1, id2, id3;

    ca_cert = GTK_WIDGET(gtk_builder_get_object(builder, "user_tls_ca_cert_chooser"));
    cert    = GTK_WIDGET(gtk_builder_get_object(builder, "user_tls_cert_chooser"));
    key     = GTK_WIDGET(gtk_builder_get_object(builder, "user_tls_private_key_chooser"));

    filter = tls_cert_filter();
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(ca_cert), filter);
    filter = all_files_filter();
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(ca_cert), filter);
    gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(ca_cert), TRUE);
    gtk_file_chooser_button_set_title(GTK_FILE_CHOOSER_BUTTON(ca_cert),
                                      _("Choose a Certificate Authority certificate…"));

    filter = tls_cert_filter();
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(cert), filter);
    filter = all_files_filter();
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(cert), filter);
    gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(cert), TRUE);
    gtk_file_chooser_button_set_title(GTK_FILE_CHOOSER_BUTTON(cert),
                                      _("Choose your personal certificate…"));

    filter = tls_key_filter();
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(key), filter);
    filter = all_files_filter();
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(key), filter);
    gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(key), TRUE);
    gtk_file_chooser_button_set_title(GTK_FILE_CHOOSER_BUTTON(key), _("Choose your private key…"));

    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_USER_CA);
        if (value && value[0])
            gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(ca_cert), value);

        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_USER_CERT);
        if (value && value[0])
            gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(cert), value);

        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_USER_KEY);
        if (value && value[0])
            gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(key), value);
    }

    /* Fill in the private key password */
    widget        = GTK_WIDGET(gtk_builder_get_object(builder, "user_tls_key_pw_entry"));
    show_password = GTK_WIDGET(gtk_builder_get_object(builder, "show_user_tls_key_pw_check"));
    g_signal_connect(show_password, "toggled", G_CALLBACK(show_password_cb), widget);

    value = nm_setting_vpn_get_secret(s_vpn, NM_L2TP_KEY_USER_CERTPASS);
    if (value)
        gtk_entry_set_text(GTK_ENTRY(widget), value);

    g_signal_connect(widget, "changed", G_CALLBACK(stuff_changed_cb), user_data);

    nma_utils_setup_password_storage(widget,
                                     0,
                                     (NMSetting *) s_vpn,
                                     NM_L2TP_KEY_USER_CERTPASS,
                                     TRUE,
                                     FALSE);

    /* Link choosers to the PKCS#12 changer callback */
    id1 = g_signal_connect(ca_cert, "selection-changed", G_CALLBACK(tls_cert_changed_cb), builder);
    id2 = g_signal_connect(cert, "selection-changed", G_CALLBACK(tls_cert_changed_cb), builder);
    id3 = g_signal_connect(key, "selection-changed", G_CALLBACK(tls_cert_changed_cb), builder);

    /* Store handler id to be able to block the signal in tls_cert_changed_cb() */
    g_object_set_data(G_OBJECT(ca_cert), BLOCK_HANDLER_ID, GSIZE_TO_POINTER(id1));
    g_object_set_data(G_OBJECT(cert), BLOCK_HANDLER_ID, GSIZE_TO_POINTER(id2));
    g_object_set_data(G_OBJECT(key), BLOCK_HANDLER_ID, GSIZE_TO_POINTER(id3));

    g_signal_connect(G_OBJECT(ca_cert),
                     "selection-changed",
                     G_CALLBACK(stuff_changed_cb),
                     user_data);
    g_signal_connect(G_OBJECT(cert), "selection-changed", G_CALLBACK(stuff_changed_cb), user_data);
    g_signal_connect(G_OBJECT(key), "selection-changed", G_CALLBACK(stuff_changed_cb), user_data);

    tls_cert_changed_cb(cert, builder);
}

static gboolean
init_plugin_ui(L2tpPluginUiWidget *self,
               gboolean            have_ipsec,
               NMConnection *      connection,
               GError **           error)
{
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    NMSettingVpn *             s_vpn;
    GtkWidget *                widget;
    GtkListStore *             store;
    GtkTreeIter                iter;
    int                        active = -1;
    const char *               value;
    const char *               authtype = NM_L2TP_AUTHTYPE_PASSWORD;

    s_vpn = nm_connection_get_setting_vpn(connection);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "gateway_entry"));
    g_return_val_if_fail(widget != NULL, FALSE);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_GATEWAY);
        if (value)
            gtk_entry_set_text(GTK_ENTRY(widget), value);
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(stuff_changed_cb), self);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "auth_combo"));
    g_return_val_if_fail(widget != NULL, FALSE);

#ifdef USE_EAPTLS
    if (s_vpn) {
        authtype = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_USER_AUTH_TYPE);
        if (authtype) {
            if (strcmp(authtype, NM_L2TP_AUTHTYPE_TLS)
                && strcmp(authtype, NM_L2TP_AUTHTYPE_PASSWORD))
                authtype = NM_L2TP_AUTHTYPE_PASSWORD;
        } else
            authtype = NM_L2TP_AUTHTYPE_PASSWORD;
    }
#else
    authtype = NM_L2TP_AUTHTYPE_PASSWORD;
#endif

    store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

    /* Password auth widget */
    pw_setup(priv->builder, s_vpn, stuff_changed_cb, self);
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store,
                       &iter,
                       COL_AUTH_NAME,
                       _("Password"),
                       COL_AUTH_PAGE,
                       0,
                       COL_AUTH_TYPE,
                       NM_L2TP_AUTHTYPE_PASSWORD,
                       -1);

    /* TLS auth widget */
    tls_setup(priv->builder, s_vpn, self);
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store,
                       &iter,
                       COL_AUTH_NAME,
                       _("Certificates (TLS)"),
                       COL_AUTH_PAGE,
                       1,
                       COL_AUTH_TYPE,
                       NM_L2TP_AUTHTYPE_TLS,
                       -1);

    if ((active < 0) && !strcmp(authtype, NM_L2TP_AUTHTYPE_TLS))
        active = 1;

    gtk_combo_box_set_model(GTK_COMBO_BOX(widget), GTK_TREE_MODEL(store));
    g_object_unref(store);
    g_signal_connect(widget, "changed", G_CALLBACK(auth_combo_changed_cb), self);
    gtk_combo_box_set_active(GTK_COMBO_BOX(widget), active < 0 ? 0 : active);

#ifndef USE_EAPTLS
    /* If not using EAP TLS pppd patch, then grey out the machine auth type selection */
    gtk_widget_set_sensitive(widget, FALSE);
    gtk_widget_set_tooltip_text(widget, "");
    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "auth_type_label"));
    gtk_widget_set_sensitive(widget, FALSE);
#endif

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ppp_button"));
    g_return_val_if_fail(widget != NULL, FALSE);
    g_signal_connect(G_OBJECT(widget), "clicked", G_CALLBACK(ppp_button_clicked_cb), self);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipsec_button"));
    g_return_val_if_fail(widget != NULL, FALSE);
    if (have_ipsec) {
        g_signal_connect(G_OBJECT(widget), "clicked", G_CALLBACK(ipsec_button_clicked_cb), self);
    } else {
        gtk_widget_set_sensitive(widget, FALSE);
    }

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ephemeral_checkbutton"));
    g_return_val_if_fail(widget != NULL, FALSE);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_EPHEMERAL_PORT);
        if (value && !strcmp(value, "yes")) {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
        } else {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), FALSE);
        }
    }
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(stuff_changed_cb), self);

    return TRUE;
}

static GObject *
get_widget(NMVpnEditor *iface)
{
    L2tpPluginUiWidget *       self = L2TP_PLUGIN_UI_WIDGET(iface);
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);

    return G_OBJECT(priv->widget);
}

static void
copy_hash_pair(gpointer key, gpointer data, gpointer user_data)
{
    NMSettingVpn *s_vpn = NM_SETTING_VPN(user_data);
    const char *  value = (const char *) data;

    g_return_if_fail(value && value[0]);

    /* IPsec PSK and certificate password is a secret, not a data item */
    if (!strcmp(key, NM_L2TP_KEY_IPSEC_PSK)) {
        /* Migrate legacy non-secret PSK data items to VPN secret */
        nm_setting_vpn_remove_data_item(s_vpn, (const char *) key);
        nm_setting_vpn_add_secret(s_vpn, (const char *) key, value);
    } else if (!strcmp(key, NM_L2TP_KEY_MACHINE_CERTPASS)) {
        nm_setting_vpn_add_secret(s_vpn, (const char *) key, value);
    } else {
        nm_setting_vpn_add_data_item(s_vpn, (const char *) key, value);
    }
}

static char *
get_auth_type(GtkBuilder *builder)
{
    GtkComboBox * combo;
    GtkTreeModel *model;
    GtkTreeIter   iter;
    char *        auth_type = NULL;
    gboolean      success;

    combo = GTK_COMBO_BOX(GTK_WIDGET(gtk_builder_get_object(builder, "auth_combo")));
    model = gtk_combo_box_get_model(combo);

    success = gtk_combo_box_get_active_iter(combo, &iter);
    g_return_val_if_fail(success == TRUE, NULL);
    gtk_tree_model_get(model, &iter, COL_AUTH_TYPE, &auth_type, -1);

    return auth_type;
}

static gboolean
update_connection(NMVpnEditor *iface, NMConnection *connection, GError **error)
{
    L2tpPluginUiWidget *       self = L2TP_PLUGIN_UI_WIDGET(iface);
    L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    NMSettingVpn *             s_vpn;
    GtkWidget *                widget;
    char *                     auth_type;
    const char *               str;
    gboolean                   valid = FALSE;

    if (!check_validity(self, error))
        return FALSE;

    s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_L2TP, NULL);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "gateway_entry"));
    str    = gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && str[0])
        nm_setting_vpn_add_data_item(s_vpn, NM_L2TP_KEY_GATEWAY, str);

    auth_type = get_auth_type(priv->builder);
    if (auth_type) {
        nm_setting_vpn_add_data_item(s_vpn, NM_L2TP_KEY_USER_AUTH_TYPE, auth_type);
        if (!strcmp(auth_type, NM_L2TP_AUTHTYPE_TLS)) {
            update_tls(priv->builder, s_vpn);
        } else if (!strcmp(auth_type, NM_L2TP_AUTHTYPE_PASSWORD)) {
            update_pw(priv->builder, s_vpn);
        }
        g_free(auth_type);
    }

    if (priv->ppp)
        g_hash_table_foreach(priv->ppp, copy_hash_pair, s_vpn);

    if (priv->ipsec)
        g_hash_table_foreach(priv->ipsec, copy_hash_pair, s_vpn);

    /* Default to agent-owned secrets for new connections */
    if (priv->new_connection) {
        if (nm_setting_vpn_get_secret(s_vpn, NM_L2TP_KEY_PASSWORD)) {
            nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                        NM_L2TP_KEY_PASSWORD,
                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                        NULL);
        }

        if (nm_setting_vpn_get_secret(s_vpn, NM_L2TP_KEY_USER_CERTPASS)) {
            nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                        NM_L2TP_KEY_USER_CERTPASS,
                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                        NULL);
        }
    }

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ephemeral_checkbutton"));
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
        nm_setting_vpn_add_data_item(s_vpn, NM_L2TP_KEY_EPHEMERAL_PORT, "yes");

    nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    valid = TRUE;

    return valid;
}

static void
is_new_func(const char *key, const char *value, gpointer user_data)
{
    gboolean *is_new = user_data;

    /* If there are any VPN data items the connection isn't new */
    *is_new = FALSE;
}

/*****************************************************************************/

static void
l2tp_plugin_ui_widget_init(L2tpPluginUiWidget *plugin)
{}

NMVpnEditor *
nm_vpn_plugin_ui_widget_interface_new(NMConnection *connection, GError **error)
{
    NMVpnEditor *              object;
    L2tpPluginUiWidgetPrivate *priv;
    gboolean new             = TRUE;
    gboolean      have_ipsec = FALSE;
    NMSettingVpn *s_vpn;

    if (error)
        g_return_val_if_fail(*error == NULL, NULL);

    object = NM_VPN_EDITOR(g_object_new(L2TP_TYPE_PLUGIN_UI_WIDGET, NULL));
    if (!object) {
        g_set_error(error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not create l2tp object"));
        return NULL;
    }

    priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(object);

    priv->builder = gtk_builder_new();

    gtk_builder_set_translation_domain(priv->builder, GETTEXT_PACKAGE);

    if (!gtk_builder_add_from_resource(priv->builder,
                                       "/org/freedesktop/network-manager-l2tp/nm-l2tp-dialog.ui",
                                       error)) {
        g_object_unref(object);
        return NULL;
    }

    priv->widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "l2tp-vbox"));
    if (!priv->widget) {
        g_set_error(error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not load UI widget"));
        g_object_unref(object);
        return NULL;
    }
    g_object_ref_sink(priv->widget);

    priv->window_group = gtk_window_group_new();

    s_vpn = nm_connection_get_setting_vpn(connection);
    if (s_vpn)
        nm_setting_vpn_foreach_data_item(s_vpn, is_new_func, &new);
    priv->new_connection = new;

    have_ipsec = nm_find_ipsec() != NULL;
    if (!init_plugin_ui(L2TP_PLUGIN_UI_WIDGET(object), have_ipsec, connection, error)) {
        g_object_unref(object);
        return NULL;
    }

    priv->ppp = ppp_dialog_new_hash_from_connection(connection, error);
    if (!priv->ppp) {
        g_object_unref(object);
        return NULL;
    }

    if (have_ipsec) {
        priv->ipsec = ipsec_dialog_new_hash_from_connection(connection, error);
        if (!priv->ipsec) {
            g_object_unref(object);
            return NULL;
        }
    } else {
        priv->ipsec = NULL;
    }

    return object;
}

static void
dispose(GObject *object)
{
    L2tpPluginUiWidget *       plugin = L2TP_PLUGIN_UI_WIDGET(object);
    L2tpPluginUiWidgetPrivate *priv   = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(plugin);

    if (priv->window_group)
        g_object_unref(priv->window_group);

    if (priv->widget)
        g_object_unref(priv->widget);

    if (priv->builder)
        g_object_unref(priv->builder);

    if (priv->ppp)
        g_hash_table_destroy(priv->ppp);

    if (priv->ipsec)
        g_hash_table_destroy(priv->ipsec);

    G_OBJECT_CLASS(l2tp_plugin_ui_widget_parent_class)->dispose(object);
}

static void
l2tp_plugin_ui_widget_class_init(L2tpPluginUiWidgetClass *req_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(req_class);

    g_type_class_add_private(req_class, sizeof(L2tpPluginUiWidgetPrivate));

    object_class->dispose = dispose;
}

static void
l2tp_plugin_ui_widget_interface_init(NMVpnEditorInterface *iface_class)
{
    iface_class->get_widget        = get_widget;
    iface_class->update_connection = update_connection;
}

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_l2tp(NMVpnEditorPlugin *editor_plugin,
                           NMConnection *     connection,
                           GError **          error)
{
    g_return_val_if_fail(!error || !*error, NULL);

    return nm_vpn_plugin_ui_widget_interface_new(connection, error);
}

/*****************************************************************************/
