/* SPDX-License-Identifier: GPL-2.0-or-later */
/***************************************************************************
 *
 * Copyright (C) 2011 Geo Carncross, <geocar@gmail.com>
 *
 */

#include "nm-default.h"

#include <nma-cert-chooser.h>

#include "ipsec-dialog.h"
#include "nm-l2tp-editor.h"

#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-secret-utils.h"
#include "shared/nm-l2tp-crypto-openssl.h"
#include "shared/utils.h"

#include "auth-helpers.h"

#define DEFAULT_IPSEC_STRONGSWAN_IKELIFETIME 10800 /* 3h */
#define DEFAULT_IPSEC_STRONGSWAN_LIFETIME    3600  /* 1h */

#define DEFAULT_IPSEC_LIBRESWAN_IKELIFETIME 3600  /* 1h */
#define DEFAULT_IPSEC_LIBRESWAN_SALIFETIME  28800 /* 8h */

static const char *ipsec_keys[] = {NM_L2TP_KEY_IPSEC_ENABLE,
                                   NM_L2TP_KEY_IPSEC_REMOTE_ID,
                                   NM_L2TP_KEY_MACHINE_AUTH_TYPE,
                                   NM_L2TP_KEY_IPSEC_PSK,
                                   NM_L2TP_KEY_MACHINE_CA,
                                   NM_L2TP_KEY_MACHINE_CERT,
                                   NM_L2TP_KEY_MACHINE_KEY,
                                   NM_L2TP_KEY_MACHINE_CERTPASS,
                                   NM_L2TP_KEY_IPSEC_IKE,
                                   NM_L2TP_KEY_IPSEC_ESP,
                                   NM_L2TP_KEY_IPSEC_IKELIFETIME,
                                   NM_L2TP_KEY_IPSEC_SALIFETIME,
                                   NM_L2TP_KEY_IPSEC_FORCEENCAPS,
                                   NM_L2TP_KEY_IPSEC_IPCOMP,
                                   NM_L2TP_KEY_IPSEC_IKEV2,
                                   NM_L2TP_KEY_IPSEC_PFS,
                                   NULL};

static void
hash_copy_value(const char *key, const char *value, gpointer user_data)
{
    GHashTable * hash = (GHashTable *) user_data;
    const char **i;

    for (i = &ipsec_keys[0]; *i; i++) {
        if (strcmp(key, *i))
            continue;
        g_hash_table_insert(hash, g_strdup(key), g_strdup(value));
    }
}

GHashTable *
ipsec_dialog_new_hash_from_connection(NMConnection *connection, GError **error)
{
    GHashTable *  hash;
    NMSettingVpn *s_vpn;
    const char *  secret, *flags;

    hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    s_vpn = nm_connection_get_setting_vpn(connection);
    nm_setting_vpn_foreach_data_item(s_vpn, hash_copy_value, hash);

    /* IPSEC PSK is special */
    secret = nm_setting_vpn_get_secret_or_legacy_data_item(s_vpn, NM_L2TP_KEY_IPSEC_PSK);
    if (secret) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PSK), g_strdup(secret));
    }

    flags = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_IPSEC_PSK "-flags");
    if (flags)
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PSK "-flags"), g_strdup(flags));

    /* IPsec certificate password is special */
    secret = nm_setting_vpn_get_secret(s_vpn, NM_L2TP_KEY_MACHINE_CERTPASS);
    if (secret) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_CERTPASS), g_strdup(secret));
    }

    flags = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_MACHINE_CERTPASS "-flags");
    if (flags)
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_CERTPASS "-flags"), g_strdup(flags));

    return hash;
}

static void
ipsec_auth_combo_changed_cb(GtkWidget *combo, gpointer user_data)
{
    GtkBuilder *  builder = GTK_BUILDER(user_data);
    GtkWidget *   widget;
    GtkTreeModel *model;
    GtkTreeIter   iter;
    gint          new_page = 0;

    model = gtk_combo_box_get_model(GTK_COMBO_BOX(combo));
    g_assert(gtk_combo_box_get_active_iter(GTK_COMBO_BOX(combo), &iter));
    gtk_tree_model_get(model, &iter, COL_AUTH_PAGE, &new_page, -1);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_tls_vbox"));
    if (new_page == 0) {
        gtk_widget_hide(widget);
    } else {
        gtk_widget_show(widget);
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_auth_notebook"));
    gtk_notebook_set_current_page(GTK_NOTEBOOK(widget), new_page);
}

static void
ipsec_toggled_cb(GtkWidget *check, gpointer user_data)
{
    GtkBuilder *builder = (GtkBuilder *) user_data;
    gboolean    sensitive;
    GtkWidget * widget;
    guint32     i         = 0;
    const char *widgets[] = {"machine_auth_label",
                             "ipsec_auth_type_label",
                             "ipsec_auth_combo",
                             "show_psk_check",
                             "psk_label",
                             "ipsec_psk_entry",
                             "advanced_label",
                             NULL};

    sensitive = gtk_check_button_get_active(GTK_CHECK_BUTTON(check));

    while (widgets[i]) {
        widget = GTK_WIDGET(gtk_builder_get_object(builder, widgets[i++]));
        gtk_widget_set_sensitive(widget, sensitive);
    }

    if (!sensitive) {
        widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_auth_combo"));
        gtk_combo_box_set_active(GTK_COMBO_BOX(widget), 0);
        ipsec_auth_combo_changed_cb(widget, builder);

        widget = GTK_WIDGET(gtk_builder_get_object(builder, "show_psk_check"));
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), FALSE);

        widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_psk_entry"));
        gtk_entry_set_visibility(GTK_ENTRY(widget), FALSE);
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "advanced_expander"));
    if (!sensitive)
        gtk_expander_set_expanded(GTK_EXPANDER(widget), FALSE);
    gtk_widget_set_sensitive(widget, sensitive);
}

static void
tls_cert_changed_cb(GtkWidget *chooser, gpointer user_data)
{
    NMACertChooser *this = NMA_CERT_CHOOSER(chooser);
    NMACertChooser *       ca_cert, *cert;
    GtkBuilder *           builder = (GtkBuilder *) user_data;
    char *                 fname, *dirname, *ca_cert_fname, *cert_fname, *key_fname;
    NML2tpCryptoFileFormat tls_fileformat = NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN;
    gboolean               tls_need_password;
    GError *               config_error     = NULL;
    gulong                 id, id1, id2;

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

    fname = nma_cert_chooser_get_cert(this, NULL);
    if (fname)
        dirname = g_path_get_dirname(fname);
    else
        dirname = NULL;

    ca_cert = NMA_CERT_CHOOSER(gtk_builder_get_object(builder, "machine_ca_chooser"));
    cert    = NMA_CERT_CHOOSER(gtk_builder_get_object(builder, "machine_cert_chooser"));

    ca_cert_fname = nma_cert_chooser_get_cert(ca_cert, NULL);
    cert_fname    = nma_cert_chooser_get_cert(cert, NULL);
    key_fname     = nma_cert_chooser_get_key(cert, NULL);

    id  = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(this), BLOCK_HANDLER_ID));
    id1 = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(ca_cert), BLOCK_HANDLER_ID));
    id2 = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(cert), BLOCK_HANDLER_ID));

    g_signal_handler_block(ca_cert, id1);
    g_signal_handler_block(cert, id2);

    tls_fileformat = crypto_file_format(fname, &tls_need_password, &config_error);
    if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
        /* Make sure all choosers have this PKCS#12 file */
        if (!nm_streq0(fname, ca_cert_fname))
            nma_cert_chooser_set_cert(NMA_CERT_CHOOSER(ca_cert), fname, NM_SETTING_802_1X_CK_SCHEME_PATH);
        if (!nm_streq0(fname, cert_fname))
            nma_cert_chooser_set_cert(NMA_CERT_CHOOSER(cert), fname, NM_SETTING_802_1X_CK_SCHEME_PATH);
        if (!nm_streq0(fname, key_fname))
            nma_cert_chooser_set_key(NMA_CERT_CHOOSER(cert), fname, NM_SETTING_802_1X_CK_SCHEME_PATH);

    } else {
        /**
         * Just-chosen file isn't PKCS#12 or no file was chosen, so clear out other
         * file selectors that have PKCS#12 files in them.
         * Set directory of unset file choosers to the directory just selected.
         **/
        if (id != id1) {
            tls_fileformat = crypto_file_format(ca_cert_fname, NULL, &config_error);
            if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
                nma_cert_chooser_set_cert(NMA_CERT_CHOOSER(ca_cert), NULL, NM_SETTING_802_1X_CK_SCHEME_PATH);
            }
        }
        if (id != id2) {
            tls_fileformat = crypto_file_format(cert_fname, NULL, &config_error);
            if (tls_fileformat == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12) {
                nma_cert_chooser_set_cert(NMA_CERT_CHOOSER(cert), NULL, NM_SETTING_802_1X_CK_SCHEME_PATH);
                nma_cert_chooser_set_key(NMA_CERT_CHOOSER(cert), NULL, NM_SETTING_802_1X_CK_SCHEME_PATH);
            }
        }
    }

    g_signal_handler_unblock(ca_cert, id1);
    g_signal_handler_unblock(cert, id2);

    g_free(fname);
    g_free(dirname);
    g_free(ca_cert_fname);
    g_free(cert_fname);
    g_free(key_fname);
    crypto_deinit_openssl();
}

static void
ipsec_tls_setup(GtkBuilder *builder, GHashTable *hash)
{
    GtkWidget *          ca_cert;
    GtkWidget *          cert;
    GtkSizeGroup *       labels;
    const char *         value;
    gulong               id1, id2;

    ca_cert = GTK_WIDGET(gtk_builder_get_object(builder, "machine_ca_chooser"));
    cert    = GTK_WIDGET(gtk_builder_get_object(builder, "machine_cert_chooser"));
    labels  = GTK_SIZE_GROUP(gtk_builder_get_object(builder, "ipsec_labels"));

    nma_cert_chooser_add_to_size_group(NMA_CERT_CHOOSER(ca_cert), labels);
    nma_cert_chooser_add_to_size_group(NMA_CERT_CHOOSER(cert), labels);

    value = g_hash_table_lookup(hash, NM_L2TP_KEY_MACHINE_CA);
    if (value && value[0])
        nma_cert_chooser_set_cert(NMA_CERT_CHOOSER(ca_cert), value, NM_SETTING_802_1X_CK_SCHEME_PATH);

    value = g_hash_table_lookup(hash, NM_L2TP_KEY_MACHINE_CERT);
    if (value && value[0])
        nma_cert_chooser_set_cert(NMA_CERT_CHOOSER(cert), value, NM_SETTING_802_1X_CK_SCHEME_PATH);

    value = g_hash_table_lookup(hash, NM_L2TP_KEY_MACHINE_KEY);
    if (value && value[0])
        nma_cert_chooser_set_key(NMA_CERT_CHOOSER(cert), value, NM_SETTING_802_1X_CK_SCHEME_PATH);

    /* Fill in the private key password */
    value = g_hash_table_lookup(hash, NM_L2TP_KEY_MACHINE_CERTPASS);
    if (value)
        nma_cert_chooser_set_key_password(NMA_CERT_CHOOSER(cert), value);

    /* Link choosers to the PKCS#12 changer callback */
    id1 = g_signal_connect(ca_cert, "changed", G_CALLBACK(tls_cert_changed_cb), builder);
    id2 = g_signal_connect(cert, "changed", G_CALLBACK(tls_cert_changed_cb), builder);

    /* Store handler id to be able to block the signal in tls_cert_changed_cb() */
    g_object_set_data(G_OBJECT(ca_cert), BLOCK_HANDLER_ID, GSIZE_TO_POINTER(id1));
    g_object_set_data(G_OBJECT(cert), BLOCK_HANDLER_ID, GSIZE_TO_POINTER(id2));

    tls_cert_changed_cb(cert, builder);
}

static void
ipsec_psk_setup(GtkBuilder *builder, GHashTable *hash)
{
    NMSettingSecretFlags pw_flags;
    GtkWidget *          psk_entry_widget;
    GtkWidget *          checkbutton_widget;
    const char *         value;
    guchar *             decoded = NULL;
    char *               psk     = NULL;
    gsize                len     = 0;

    checkbutton_widget = GTK_WIDGET(gtk_builder_get_object(builder, "show_psk_check"));
    psk_entry_widget   = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_psk_entry"));

    value = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_PSK);
    if (value && value[0]) {
        if (g_str_has_prefix(value, "0s")) { /* Base64 encoded PSK */
            decoded = g_base64_decode(value + 2, &len);
            if (decoded && len > 0) {
                /* ensure PSK is NULL terminated string */
                psk = g_malloc0(len + 1);
                memcpy(psk, decoded, len);
                gtk_editable_set_text(GTK_EDITABLE(psk_entry_widget), psk);
                g_free(psk);
            }
            g_free(decoded);
        } else {
            gtk_editable_set_text(GTK_EDITABLE(psk_entry_widget), value);
        }
    }

    g_signal_connect(checkbutton_widget, "toggled", G_CALLBACK(show_password_cb), psk_entry_widget);

    value = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_PSK "-flags");
    if (value) {
        G_STATIC_ASSERT_EXPR(((guint) (NMSettingSecretFlags) 0xFFFFu) == 0xFFFFu);
        pw_flags = _nm_utils_ascii_str_to_int64(value, 10, 0, 0xFFFF, NM_SETTING_SECRET_FLAG_NONE);
    } else {
        pw_flags = NM_SETTING_SECRET_FLAG_NONE;
    }

    nma_utils_setup_password_storage(psk_entry_widget,
                                     pw_flags,
                                     NULL,
                                     NM_L2TP_KEY_IPSEC_PSK,
                                     FALSE,
                                     FALSE);
}

static void
remote_id_toggled_cb(GtkCheckButton *button, gpointer user_data)
{
    GtkBuilder *builder = GTK_BUILDER(user_data);
    GtkWidget * widget;
    gboolean    sensitive;

    sensitive = gtk_check_button_get_active(GTK_CHECK_BUTTON(button));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_remote_id_entry"));
    gtk_widget_set_sensitive(widget, sensitive);
    if (!sensitive) {
        gtk_editable_set_text(GTK_EDITABLE(widget), "");
    }
}

static void
phase1_toggled_cb(GtkCheckButton *button, gpointer user_data)
{
    GtkBuilder *builder = GTK_BUILDER(user_data);
    GtkWidget * widget;
    gboolean    sensitive;

    sensitive = gtk_check_button_get_active(GTK_CHECK_BUTTON(button));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase1_entry"));
    gtk_widget_set_sensitive(widget, sensitive);
    if (!sensitive) {
        gtk_editable_set_text(GTK_EDITABLE(widget), "");
    }
}

static void
phase2_toggled_cb(GtkCheckButton *button, gpointer user_data)
{
    GtkBuilder *builder = GTK_BUILDER(user_data);
    GtkWidget * widget;
    gboolean    sensitive;

    sensitive = gtk_check_button_get_active(GTK_CHECK_BUTTON(button));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase2_entry"));
    gtk_widget_set_sensitive(widget, sensitive);
    if (!sensitive) {
        gtk_editable_set_text(GTK_EDITABLE(widget), "");
    }
}

static void
lifetime1_toggled_cb(GtkCheckButton *button, gpointer user_data)
{
    GtkBuilder *      builder = GTK_BUILDER(user_data);
    GtkWidget *       widget;
    gboolean          sensitive;
    NML2tpIpsecDaemon ipsec_daemon;

    sensitive = gtk_check_button_get_active(GTK_CHECK_BUTTON(button));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase1_lifetime"));
    gtk_widget_set_sensitive(widget, sensitive);
    if (!sensitive) {
        ipsec_daemon = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "ipsec-daemon"));
        if (ipsec_daemon == NM_L2TP_IPSEC_DAEMON_STRONGSWAN)
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget),
                                      DEFAULT_IPSEC_STRONGSWAN_IKELIFETIME);
        else
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), DEFAULT_IPSEC_LIBRESWAN_IKELIFETIME);
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "phase1_lifetime_label"));
    gtk_widget_set_sensitive(widget, sensitive);
}

static void
lifetime2_toggled_cb(GtkCheckButton *button, gpointer user_data)
{
    GtkBuilder *      builder = GTK_BUILDER(user_data);
    GtkWidget *       widget;
    gboolean          sensitive;
    NML2tpIpsecDaemon ipsec_daemon;

    sensitive = gtk_check_button_get_active(GTK_CHECK_BUTTON(button));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase2_lifetime"));
    gtk_widget_set_sensitive(widget, sensitive);
    if (!sensitive) {
        ipsec_daemon = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "ipsec-daemon"));
        if (ipsec_daemon == NM_L2TP_IPSEC_DAEMON_STRONGSWAN)
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), DEFAULT_IPSEC_STRONGSWAN_LIFETIME);
        else
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), DEFAULT_IPSEC_LIBRESWAN_SALIFETIME);
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "phase2_lifetime_label"));
    gtk_widget_set_sensitive(widget, sensitive);
}

static gint
lifetime_spin_input(GtkSpinButton *spin_button, gdouble *new_val)
{
    GtkAdjustment *adjustment;
    const gchar *  text;
    int            hours;
    int            minutes;

    adjustment = gtk_spin_button_get_adjustment(spin_button);
    *new_val   = gtk_adjustment_get_value(adjustment);
    text       = gtk_editable_get_text(GTK_EDITABLE(spin_button));
    if (sscanf(text, "%d:%d", &hours, &minutes) != 2) {
        return GTK_INPUT_ERROR;
    }

    if (0 <= hours && hours <= 24 && 0 <= minutes && minutes < 60) {
        *new_val = hours * 3600 + minutes * 60;
        return TRUE;
    }

    return GTK_INPUT_ERROR;
}

static gint
lifetime_spin_output(GtkSpinButton *spin_button)
{
    GtkAdjustment *adjustment;
    gchar *        buf;
    int            hours;
    int            minutes;
    int            seconds;

    adjustment = gtk_spin_button_get_adjustment(spin_button);
    seconds    = (int) gtk_adjustment_get_value(adjustment);
    hours      = seconds / 3600;
    minutes    = (seconds % 3600) / 60;
    buf        = g_strdup_printf("%d:%02d", hours, minutes);
    if (strcmp(buf, gtk_editable_get_text(GTK_EDITABLE(spin_button))))
        gtk_editable_set_text(GTK_EDITABLE(spin_button), buf);
    g_free(buf);

    return TRUE;
}

GtkWidget *
ipsec_dialog_new(GHashTable *hash)
{
    GtkBuilder *      builder;
    GtkWidget *       dialog = NULL;
    GtkWidget *       widget;
    GtkListStore *    store;
    GtkTreeIter       iter;
    int               active = -1;
    const char *      value;
    gboolean          expand;
    gboolean          sensitive;
    GError *          error = NULL;
    const char *      tooltip_text;
    const char *      authtype = NM_L2TP_AUTHTYPE_PASSWORD;
    NML2tpIpsecDaemon ipsec_daemon;

    g_return_val_if_fail(hash != NULL, NULL);

    builder = gtk_builder_new();

    if (!gtk_builder_add_from_resource(builder,
                                       "/org/freedesktop/network-manager-l2tp/nm-l2tp-dialog.ui",
                                       &error)) {
        g_warning("Couldn't load builder file: %s", error ? error->message : "(unknown)");
        g_clear_error(&error);
        g_object_unref(G_OBJECT(builder));
        return NULL;
    }
    gtk_builder_set_translation_domain(builder, GETTEXT_PACKAGE);

    dialog = GTK_WIDGET(gtk_builder_get_object(builder, "l2tp-ipsec-dialog"));
    if (!dialog) {
        g_object_unref(G_OBJECT(builder));
        return NULL;
    }
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);

    g_object_set_data_full(G_OBJECT(dialog),
                           "gtkbuilder-xml",
                           builder,
                           (GDestroyNotify) g_object_unref);

    authtype = g_hash_table_lookup(hash, NM_L2TP_KEY_MACHINE_AUTH_TYPE);
    if (authtype) {
        if (strcmp(authtype, NM_L2TP_AUTHTYPE_TLS) && strcmp(authtype, NM_L2TP_AUTHTYPE_PSK))
            authtype = NM_L2TP_AUTHTYPE_PSK;
    } else {
        authtype = NM_L2TP_AUTHTYPE_PSK;
    }
    g_object_set_data(G_OBJECT(dialog), "auth-type", GINT_TO_POINTER(authtype));

    store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

    /* PSK auth widget */
    ipsec_psk_setup(builder, hash);
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store,
                       &iter,
                       COL_AUTH_NAME,
                       _("Pre-shared key (PSK)"),
                       COL_AUTH_PAGE,
                       0,
                       COL_AUTH_TYPE,
                       NM_L2TP_AUTHTYPE_PSK,
                       -1);

    /* TLS auth widget */
    ipsec_tls_setup(builder, hash);
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

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_auth_combo"));
    gtk_combo_box_set_model(GTK_COMBO_BOX(widget), GTK_TREE_MODEL(store));
    g_object_unref(store);

    g_signal_connect(widget, "changed", G_CALLBACK(ipsec_auth_combo_changed_cb), builder);
    gtk_combo_box_set_active(GTK_COMBO_BOX(widget), active < 0 ? 0 : active);

    expand = FALSE;

    widget    = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_remote_id_entry"));
    sensitive = FALSE;
    if ((value = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_REMOTE_ID))) {
        gtk_editable_set_text(GTK_EDITABLE(widget), value);
        sensitive = TRUE;
        expand    = TRUE;
    }
    gtk_widget_set_sensitive(widget, sensitive);
    tooltip_text = gtk_widget_get_tooltip_text(widget);
    widget       = GTK_WIDGET(gtk_builder_get_object(builder, "remote_id_check"));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), sensitive);
    gtk_widget_set_tooltip_text(widget, tooltip_text);
    remote_id_toggled_cb(GTK_CHECK_BUTTON(widget), builder);
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(remote_id_toggled_cb), builder);

    /* Phase 1 Algorithms: IKE */
    widget    = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase1_entry"));
    sensitive = FALSE;
    if ((value = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_IKE))) {
        gtk_editable_set_text(GTK_EDITABLE(widget), value);
        sensitive = TRUE;
        expand    = TRUE;
    }
    gtk_widget_set_sensitive(widget, sensitive);
    tooltip_text = gtk_widget_get_tooltip_text(widget);
    widget       = GTK_WIDGET(gtk_builder_get_object(builder, "phase1_check"));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), sensitive);
    gtk_widget_set_tooltip_text(widget, tooltip_text);
    phase1_toggled_cb(GTK_CHECK_BUTTON(widget), builder);
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(phase1_toggled_cb), builder);

    /* Phase 2 Algorithms: ESP */
    widget    = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase2_entry"));
    sensitive = FALSE;
    if ((value = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_ESP))) {
        gtk_editable_set_text(GTK_EDITABLE(widget), value);
        sensitive = TRUE;
        expand    = TRUE;
    }
    gtk_widget_set_sensitive(widget, sensitive);
    tooltip_text = gtk_widget_get_tooltip_text(widget);
    widget       = GTK_WIDGET(gtk_builder_get_object(builder, "phase2_check"));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), sensitive);
    gtk_widget_set_tooltip_text(widget, tooltip_text);
    phase2_toggled_cb(GTK_CHECK_BUTTON(widget), builder);
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(phase2_toggled_cb), builder);

    ipsec_daemon = check_ipsec_daemon(nm_find_ipsec());

    /* Phase 1 Lifetime */
    widget    = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase1_lifetime"));
    value     = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_IKELIFETIME);
    sensitive = FALSE;
    if (value && *value) {
        long int tmp_int;
        errno   = 0;
        tmp_int = strtol(value, NULL, 10);
        if (errno == 0 && tmp_int >= 0 && tmp_int <= 24 * 60 * 60) {
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), (gdouble) tmp_int);
            sensitive = TRUE;
            expand    = TRUE;
        }
    } else {
        if (ipsec_daemon == NM_L2TP_IPSEC_DAEMON_STRONGSWAN)
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget),
                                      DEFAULT_IPSEC_STRONGSWAN_IKELIFETIME);
        else
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), DEFAULT_IPSEC_LIBRESWAN_IKELIFETIME);
    }
    gtk_widget_set_sensitive(widget, sensitive);
    lifetime_spin_output(GTK_SPIN_BUTTON(widget));
    g_signal_connect(G_OBJECT(widget), "input", G_CALLBACK(lifetime_spin_input), builder);
    g_signal_connect(G_OBJECT(widget), "output", G_CALLBACK(lifetime_spin_output), builder);
    tooltip_text = gtk_widget_get_tooltip_text(widget);
    widget       = GTK_WIDGET(gtk_builder_get_object(builder, "phase1_lifetime_check"));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), sensitive);
    gtk_widget_set_tooltip_text(widget, tooltip_text);
    g_object_set_data(G_OBJECT(widget), "ipsec-daemon", GINT_TO_POINTER(ipsec_daemon));
    lifetime1_toggled_cb(GTK_CHECK_BUTTON(widget), builder);
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(lifetime1_toggled_cb), builder);
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "phase1_lifetime_label"));
    gtk_widget_set_sensitive(widget, sensitive);

    /* Phase 2 Lifetime */
    widget    = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase2_lifetime"));
    value     = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_SALIFETIME);
    sensitive = FALSE;
    if (value && *value) {
        long int tmp_int;
        errno   = 0;
        tmp_int = strtol(value, NULL, 10);
        if (errno == 0 && tmp_int >= 0 && tmp_int <= 24 * 60 * 60) {
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), (gdouble) tmp_int);
            sensitive = TRUE;
            expand    = TRUE;
        }
    } else {
        if (ipsec_daemon == NM_L2TP_IPSEC_DAEMON_STRONGSWAN)
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), DEFAULT_IPSEC_STRONGSWAN_LIFETIME);
        else
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), DEFAULT_IPSEC_LIBRESWAN_SALIFETIME);
    }
    gtk_widget_set_sensitive(widget, sensitive);
    lifetime_spin_output(GTK_SPIN_BUTTON(widget));
    g_signal_connect(G_OBJECT(widget), "input", G_CALLBACK(lifetime_spin_input), builder);
    g_signal_connect(G_OBJECT(widget), "output", G_CALLBACK(lifetime_spin_output), builder);
    tooltip_text = gtk_widget_get_tooltip_text(widget);
    widget       = GTK_WIDGET(gtk_builder_get_object(builder, "phase2_lifetime_check"));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), sensitive);
    gtk_widget_set_tooltip_text(widget, tooltip_text);
    g_object_set_data(G_OBJECT(widget), "ipsec-daemon", GINT_TO_POINTER(ipsec_daemon));
    lifetime2_toggled_cb(GTK_CHECK_BUTTON(widget), builder);
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(lifetime2_toggled_cb), builder);
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "phase2_lifetime_label"));
    gtk_widget_set_sensitive(widget, sensitive);

    value  = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_FORCEENCAPS);
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "encap_check"));
    if (value && !strcmp(value, "yes")) {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), TRUE);
        expand = TRUE;
    } else {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), FALSE);
    }

    value  = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_IPCOMP);
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipcomp_check"));
    if (value && !strcmp(value, "yes")) {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), TRUE);
        expand = TRUE;
    } else {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), FALSE);
    }

    value  = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_IKEV2);
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ikev2_check"));
    if (value && !strcmp(value, "yes")) {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), TRUE);
        expand = TRUE;
    } else {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), FALSE);
    }

    /* PFS check button is not sensitive with strongSwan as the PFS option is ignored */
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "pfs_check"));
    if (ipsec_daemon == NM_L2TP_IPSEC_DAEMON_STRONGSWAN) {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), FALSE);
        gtk_widget_set_sensitive(widget, sensitive);
        gtk_widget_set_tooltip_text(widget, NULL);
    } else {
        value = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_PFS);
        if (value && !strcmp(value, "no")) {
            gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), TRUE);
            expand = TRUE;
        } else {
            gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), FALSE);
        }
    }

    if (expand) {
        widget = GTK_WIDGET(gtk_builder_get_object(builder, "advanced_expander"));
        gtk_expander_set_expanded(GTK_EXPANDER(widget), TRUE);
    }

    value  = g_hash_table_lookup(hash, NM_L2TP_KEY_IPSEC_ENABLE);
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_check"));
    if (value && !strcmp(value, "yes")) {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), TRUE);
    }
    ipsec_toggled_cb(widget, builder);
    g_signal_connect(G_OBJECT(widget), "toggled", G_CALLBACK(ipsec_toggled_cb), builder);

    return dialog;
}

GHashTable *
ipsec_dialog_new_hash_from_dialog(GtkWidget *dialog, GError **error)
{
    GHashTable *  hash;
    GtkWidget *   widget;
    GtkBuilder *  builder;
    const gchar * value;
    GtkTreeModel *model;
    GtkTreeIter   iter;
    guint32       pw_flags;
    int           lifetime;

    g_return_val_if_fail(dialog != NULL, NULL);
    if (error)
        g_return_val_if_fail(*error == NULL, NULL);

    builder = g_object_get_data(G_OBJECT(dialog), "gtkbuilder-xml");
    g_return_val_if_fail(builder != NULL, NULL);

    hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_check"));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget)))
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_ENABLE), g_strdup("yes"));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_remote_id_entry"));
    value  = gtk_editable_get_text(GTK_EDITABLE(widget));
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_REMOTE_ID), g_strdup(value));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_auth_combo"));
    model  = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
    value  = NULL;
    if (gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget), &iter)) {
        gtk_tree_model_get(model, &iter, COL_AUTH_TYPE, &value, -1);
    }
    if (value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_AUTH_TYPE), g_strdup(value));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_psk_entry"));
    value  = gtk_editable_get_text(GTK_EDITABLE(widget));
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PSK), g_strdup(value));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "machine_ca_chooser"));
    value  = nma_cert_chooser_get_cert(NMA_CERT_CHOOSER(widget), NULL);
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_CA), g_strdup(value));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "machine_cert_chooser"));
    value  = nma_cert_chooser_get_cert(NMA_CERT_CHOOSER(widget), NULL);
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_CERT), g_strdup(value));
    }
    value  = nma_cert_chooser_get_key(NMA_CERT_CHOOSER(widget), NULL);
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_KEY), g_strdup(value));
    }
    value  = nma_cert_chooser_get_key_password(NMA_CERT_CHOOSER(widget));
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_MACHINE_CERTPASS), g_strdup(value));
    }
    pw_flags = nma_cert_chooser_get_key_password_flags(NMA_CERT_CHOOSER(widget));
    if (pw_flags != NM_SETTING_SECRET_FLAG_NONE) {
        g_hash_table_insert(hash,
                            g_strdup(NM_L2TP_KEY_MACHINE_CERTPASS "-flags"),
                            g_strdup_printf("%d", pw_flags));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase1_entry"));
    value  = gtk_editable_get_text(GTK_EDITABLE(widget));
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_IKE), g_strdup(value));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase2_entry"));
    value  = gtk_editable_get_text(GTK_EDITABLE(widget));
    if (value && *value) {
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_ESP), g_strdup(value));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "phase1_lifetime_check"));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget))) {
        widget   = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase1_lifetime"));
        lifetime = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
        g_hash_table_insert(hash,
                            g_strdup(NM_L2TP_KEY_IPSEC_IKELIFETIME),
                            g_strdup_printf("%d", lifetime));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "phase2_lifetime_check"));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget))) {
        widget   = GTK_WIDGET(gtk_builder_get_object(builder, "ipsec_phase2_lifetime"));
        lifetime = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
        g_hash_table_insert(hash,
                            g_strdup(NM_L2TP_KEY_IPSEC_SALIFETIME),
                            g_strdup_printf("%d", lifetime));
    }

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "encap_check"));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget)))
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_FORCEENCAPS), g_strdup("yes"));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ipcomp_check"));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget)))
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_IPCOMP), g_strdup("yes"));

    widget = GTK_WIDGET(gtk_builder_get_object(builder, "ikev2_check"));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget)))
        g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_IKEV2), g_strdup("yes"));

    /* PFS check button is not sensitive with strongSwan as the PFS option is ignored */
    widget = GTK_WIDGET(gtk_builder_get_object(builder, "pfs_check"));
    if (gtk_widget_get_sensitive(widget)) {
        if (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget)))
            g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PFS), g_strdup("no"));
    }

    return hash;
}
