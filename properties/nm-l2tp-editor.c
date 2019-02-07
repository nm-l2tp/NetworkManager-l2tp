/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#include "nm-default.h"

#include "nm-l2tp-editor.h"

#include <ctype.h>
#include <gtk/gtk.h>

#include "ppp-dialog.h"
#include "ipsec-dialog.h"

#include "shared/nm-l2tp-crypto-openssl.h"

/*****************************************************************************/

static void l2tp_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (L2tpPluginUiWidget, l2tp_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
						l2tp_plugin_ui_widget_interface_init))

#define L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), L2TP_TYPE_PLUGIN_UI_WIDGET, L2tpPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *ppp;
	GHashTable *ipsec;
	gboolean new_connection;
} L2tpPluginUiWidgetPrivate;

/**
 * Return copy of string #s with the leading and trailing spaces removed
 * result must be freed with g_free()
 **/
static char *
strstrip (const char *s)
{
	size_t size;
	char *end;
	char *scpy;

	/* leading */
	while (*s && isspace (*s))
		s++;

	scpy = g_strdup (s);
	size = strlen (scpy);

	if (!size)
		return scpy;

	end = scpy + size - 1;

	while (end >= scpy && isspace (*end))
		end--;
	*(end + 1) = '\0';

	return scpy;
}

static void
tls_cert_changed_cb (NMACertChooser *this, gpointer user_data)
{
	NMACertChooser *other = user_data;
	NMSetting8021xCKScheme scheme;
	gs_free char *this_cert = NULL;
	gs_free char *other_cert = NULL;
	gs_free char *this_key = NULL;
	gs_free char *other_key = NULL;

	other_key = nma_cert_chooser_get_key (other, &scheme);
	this_key = nma_cert_chooser_get_key (this, &scheme);
	other_cert = nma_cert_chooser_get_cert (other, &scheme);
	this_cert = nma_cert_chooser_get_cert (this, &scheme);
	if (   scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
	  && crypto_file_format (this_cert, NULL, NULL) == NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12)
	{
		if (!this_key)
			nma_cert_chooser_set_key (this, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
		if (!other_cert) {
			nma_cert_chooser_set_cert (other, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
			if (!other_key)
				nma_cert_chooser_set_key (other, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
		}
	}
}

static void
tls_setup (GtkBuilder *builder,
           NMSettingVpn *s_vpn,
           ChangedCallback changed_cb,
           gpointer user_data)
{
	NMACertChooser *ca_cert;
	NMACertChooser *cert;
	const char *value;

	ca_cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_user_ca_cert"));
	cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_user_cert"));

	nma_cert_chooser_add_to_size_group (ca_cert, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels")));
	nma_cert_chooser_add_to_size_group (cert, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels")));

	g_signal_connect (G_OBJECT (ca_cert), "changed", G_CALLBACK (changed_cb), user_data);
	g_signal_connect (G_OBJECT (cert), "changed", G_CALLBACK (changed_cb), user_data);

	/* Link to the PKCS#12 changer callback */
	g_signal_connect_object (ca_cert, "changed", G_CALLBACK (tls_cert_changed_cb), cert, 0);
	g_signal_connect_object (cert, "changed", G_CALLBACK (tls_cert_changed_cb), ca_cert, 0);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER_CA);
		if (value && value[0])
			nma_cert_chooser_set_cert (ca_cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER_CERT);
		if (value && value[0])
			nma_cert_chooser_set_cert (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER_KEY);
		if (value && value[0])
			nma_cert_chooser_set_key (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_USER_CERTPASS);
		if (value)
			nma_cert_chooser_set_key_password (cert, value);
	}

	nma_cert_chooser_setup_key_password_storage (cert, 0, (NMSetting *) s_vpn,
	                                             NM_L2TP_KEY_USER_CERTPASS, TRUE, FALSE);
}

static void
pw_show_toggled_cb (GtkCheckButton *button, L2tpPluginUiWidget *self)
{
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "password_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
pw_setup (GtkBuilder *builder,
          NMSettingVpn *s_vpn,
          ChangedCallback changed_cb,
          gpointer user_data)
{
	GtkWidget *widget;
	const char *value;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "username_entry"));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
		if (value && value[0])
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	/* Fill in the user password */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "password_entry"));
	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_PASSWORD);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);
	nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_vpn, NM_L2TP_KEY_PASSWORD,
	                                  TRUE, FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "domain_entry"));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_DOMAIN);
		if (value && value[0])
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	widget = GTK_WIDGET (gtk_builder_get_object (builder,  "show_password_checkbutton"));
	g_signal_connect (widget, "toggled", G_CALLBACK (pw_show_toggled_cb), user_data);
}

static void
update_from_cert_chooser (GtkBuilder *builder,
                          const char *cert_prop,
                          const char *key_prop,
                          const char *key_pass_prop,
                          const char *widget_name,
                          NMSettingVpn *s_vpn)
{
	NMSetting8021xCKScheme scheme;
	NMACertChooser *cert_chooser;
	NMSettingSecretFlags pw_flags;
	char *tmp;
	const char *password;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (cert_prop != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	cert_chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, widget_name));

	tmp = nma_cert_chooser_get_cert (cert_chooser, &scheme);
	if (tmp && tmp[0])
		nm_setting_vpn_add_data_item (s_vpn, cert_prop, tmp);
	g_free (tmp);

	if (key_prop) {
		g_return_if_fail (key_pass_prop != NULL);

		tmp = nma_cert_chooser_get_key (cert_chooser, &scheme);
		if (tmp && tmp[0])
			nm_setting_vpn_add_data_item (s_vpn, key_prop, tmp);
		g_free (tmp);

		password = nma_cert_chooser_get_key_password (cert_chooser);
		if (password && password[0])
			nm_setting_vpn_add_secret (s_vpn, key_pass_prop, password);

		pw_flags = nma_cert_chooser_get_key_password_flags (cert_chooser);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), key_pass_prop, pw_flags, NULL);
	}
}

static void
update_tls (GtkBuilder *builder, NMSettingVpn *s_vpn)
{
	update_from_cert_chooser (builder,
	                          NM_L2TP_KEY_USER_CA,
	                          NULL,
	                          NULL,
	                          "tls_user_ca_cert", s_vpn);

	update_from_cert_chooser (builder,
	                          NM_L2TP_KEY_USER_CERT,
	                          NM_L2TP_KEY_USER_KEY,
	                          NM_L2TP_KEY_USER_CERTPASS,
	                          "tls_user_cert", s_vpn);
}

static void
update_pw (GtkBuilder *builder, NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	NMSettingSecretFlags pw_flags;
	const char *str;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (s_vpn != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "username_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0])
		nm_setting_vpn_add_data_item (s_vpn, NM_L2TP_KEY_USER, str);

	widget = (GtkWidget *) gtk_builder_get_object (builder, "password_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0])
		nm_setting_vpn_add_secret (s_vpn, NM_L2TP_KEY_PASSWORD, str);
	pw_flags = nma_utils_menu_to_secret_flags (widget);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_L2TP_KEY_PASSWORD, pw_flags, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "domain_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0])
		nm_setting_vpn_add_data_item (s_vpn, NM_L2TP_KEY_DOMAIN, str);
}

static gboolean
check_validity (L2tpPluginUiWidget *self, GError **error)
{
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	char *s=NULL;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (s = strstrip (str))) {
		g_free(s);
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_L2TP_KEY_GATEWAY);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (L2TP_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
        L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (user_data);
        L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
        GtkWidget *auth_notebook;
        GtkTreeModel *model;
        GtkTreeIter iter;
        gint new_page = 0;

        model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
        g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));
        gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);

        auth_notebook = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_notebook"));
        gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

        stuff_changed_cb (combo, self);
}

static void
ppp_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

static void
ipsec_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

static void
ppp_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (user_data);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {
		ppp_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->ppp)
		g_hash_table_destroy (priv->ppp);
	priv->ppp = ppp_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->ppp) {
		g_message (_("%s: error reading ppp settings: %s"), __func__, error->message);
		g_error_free (error);
	}
	ppp_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
ipsec_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (user_data);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {
		ipsec_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->ipsec)
		g_hash_table_destroy (priv->ipsec);
	priv->ipsec = ipsec_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->ipsec) {
		g_message (_("%s: error reading ipsec settings: %s"), __func__, error->message);
		g_error_free (error);
	}
	ipsec_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
ppp_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (user_data);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel, *widget;
	GtkBuilder *builder;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *authtype = NULL;
	gboolean success;
	guint32 i = 0;
	const char *widgets[] = {
		"ppp_auth_label", "auth_methods_label", "ppp_auth_methods",
		NULL
	};
	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (gtk_widget_is_toplevel (toplevel));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	success = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	g_return_if_fail (success == TRUE);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &authtype, -1);

	dialog = ppp_dialog_new (priv->ppp, authtype);
	if (!dialog) {
		g_warning (_("%s: failed to create the PPP dialog!"), __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (ppp_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (ppp_dialog_close_cb), self);

	builder = g_object_get_data (G_OBJECT (dialog), "gtkbuilder-xml");
	g_return_if_fail (builder != NULL);

	if (authtype) {
		if (strcmp (authtype, NM_L2TP_AUTHTYPE_TLS) == 0) {
			while (widgets[i]) {
				widget = GTK_WIDGET (gtk_builder_get_object (builder, widgets[i++]));
				gtk_widget_set_sensitive (widget, FALSE);
			}
		}
	}

	gtk_widget_show_all (dialog);
}

static void
ipsec_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (user_data);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel, *widget;
	GtkBuilder *builder;
	const char *authtype = NULL;

	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (gtk_widget_is_toplevel (toplevel));

	dialog = ipsec_dialog_new (priv->ipsec);
	if (!dialog) {
		g_warning (_("%s: failed to create the IPsec dialog!"), __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (ipsec_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (ipsec_dialog_close_cb), self);

	gtk_widget_show_all (dialog);

	authtype = g_object_get_data (G_OBJECT (dialog), "auth-type");
	if (authtype) {
		if (strcmp (authtype, NM_L2TP_AUTHTYPE_TLS) != 0) {
			builder = g_object_get_data (G_OBJECT (dialog), "gtkbuilder-xml");
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_machine_cert"));
			gtk_widget_hide (widget);
		}
	}
}

static gboolean
init_plugin_ui (L2tpPluginUiWidget *self, NMConnection *connection, GError **error)
{
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;
	const char *authtype = NM_L2TP_AUTHTYPE_PASSWORD;

	s_vpn = nm_connection_get_setting_vpn (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	if (s_vpn) {
		authtype = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER_AUTH_TYPE);
		if (authtype) {
			if (   strcmp (authtype, NM_L2TP_AUTHTYPE_TLS)
			    && strcmp (authtype, NM_L2TP_AUTHTYPE_PASSWORD))
				authtype = NM_L2TP_AUTHTYPE_PASSWORD;
		} else
			authtype = NM_L2TP_AUTHTYPE_PASSWORD;
	}

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	/* Password auth widget */
	pw_setup (priv->builder, s_vpn, stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password"),
	                    COL_AUTH_PAGE, 0,
	                    COL_AUTH_TYPE, NM_L2TP_AUTHTYPE_PASSWORD,
	                    -1);

	/* TLS auth widget */
	tls_setup (priv->builder, s_vpn, stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Certificates (TLS)"),
	                    COL_AUTH_PAGE, 1,
	                    COL_AUTH_TYPE, NM_L2TP_AUTHTYPE_TLS,
	                    -1);

	if ((active < 0) && !strcmp (authtype, NM_L2TP_AUTHTYPE_TLS))
		active = 1;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ppp_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (ppp_button_clicked_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipsec_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (ipsec_button_clicked_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (iface);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
copy_hash_pair (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (user_data);
	const char *value = (const char *) data;

	g_return_if_fail (value && value[0]);

	/* IPsec certificate password is a secret, not a data item */
	if (!strcmp (key, NM_L2TP_KEY_MACHINE_CERTPASS))
		nm_setting_vpn_add_secret (s_vpn, (const char *) key, value);
	else
		nm_setting_vpn_add_data_item (s_vpn, (const char *) key, value);
}

static char *
get_auth_type (GtkBuilder *builder)
{
	GtkComboBox *combo;
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *auth_type = NULL;
	gboolean success;

	combo = GTK_COMBO_BOX (GTK_WIDGET (gtk_builder_get_object (builder, "auth_combo")));
	model = gtk_combo_box_get_model (combo);

	success = gtk_combo_box_get_active_iter (combo, &iter);
	g_return_val_if_fail (success == TRUE, NULL);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);

	return auth_type;
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	L2tpPluginUiWidget *self = L2TP_PLUGIN_UI_WIDGET (iface);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	char *auth_type;
	const char *str;
	gboolean valid = FALSE;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_L2TP, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0])
		nm_setting_vpn_add_data_item (s_vpn, NM_L2TP_KEY_GATEWAY, str);

	auth_type = get_auth_type (priv->builder);
	if (auth_type) {
		nm_setting_vpn_add_data_item (s_vpn, NM_L2TP_KEY_USER_AUTH_TYPE, auth_type);
		if (!strcmp (auth_type, NM_L2TP_AUTHTYPE_TLS)) {
			update_tls (priv->builder, s_vpn);
		} else if (!strcmp (auth_type, NM_L2TP_AUTHTYPE_PASSWORD)) {
			update_pw (priv->builder, s_vpn);
		}
		g_free (auth_type);
	}

	if (priv->ppp)
		g_hash_table_foreach (priv->ppp, copy_hash_pair, s_vpn);

	if (priv->ipsec)
		g_hash_table_foreach (priv->ipsec, copy_hash_pair, s_vpn);

	/* Default to agent-owned secrets for new connections */
	if (priv->new_connection) {
		if (nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_PASSWORD)) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_L2TP_KEY_PASSWORD,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}

		if (nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_USER_CERTPASS)) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_L2TP_KEY_USER_CERTPASS,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

/*****************************************************************************/

static void
l2tp_plugin_ui_widget_init (L2tpPluginUiWidget *plugin)
{
}

NMVpnEditor *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	L2tpPluginUiWidgetPrivate *priv;
	gboolean new = TRUE;
	NMSettingVpn *s_vpn;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_EDITOR (g_object_new (L2TP_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not create l2tp object"));
		return NULL;
	}

	priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-l2tp/nm-l2tp-dialog.ui", error)) {
		g_object_unref(object);
		return NULL;
	}

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "l2tp-vbox"));
	if (!priv->widget) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not load UI widget"));
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_plugin_ui (L2TP_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	priv->ppp = ppp_dialog_new_hash_from_connection (connection, error);
	if (!priv->ppp) {
		g_object_unref (object);
		return NULL;
	}
	priv->ipsec = ipsec_dialog_new_hash_from_connection (connection, error);
	if (!priv->ipsec) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	L2tpPluginUiWidget *plugin = L2TP_PLUGIN_UI_WIDGET (object);
	L2tpPluginUiWidgetPrivate *priv = L2TP_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	if (priv->ppp)
		g_hash_table_destroy (priv->ppp);

	if (priv->ipsec)
		g_hash_table_destroy (priv->ipsec);

	G_OBJECT_CLASS (l2tp_plugin_ui_widget_parent_class)->dispose (object);
}

static void
l2tp_plugin_ui_widget_class_init (L2tpPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (L2tpPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
l2tp_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class)
{
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

/*****************************************************************************/

#if !(NETWORKMANAGER_COMPILATION & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL)

#include "nm-l2tp-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_l2tp (NMVpnEditorPlugin *editor_plugin,
                            NMConnection *connection,
                            GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}
#endif

