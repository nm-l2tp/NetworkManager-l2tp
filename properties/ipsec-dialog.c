/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2011 Geo Carncross, <geocar@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include <glib/gi18n-lib.h>

#ifdef NM_VPN_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-connection.h>
#include <nm-setting-vpn.h>

#else /* !NM_VPN_OLD */

#include <NetworkManager.h>
#endif

#include "ipsec-dialog.h"
#include "nm-default.h"
#include "nm-l2tp-editor.h"
#include "nm-service-defines.h"

static const char *ipsec_keys[] = {
	NM_L2TP_KEY_IPSEC_ENABLE,
	NM_L2TP_KEY_IPSEC_GATEWAY_ID,
	NM_L2TP_KEY_IPSEC_PSK,
	NM_L2TP_KEY_IPSEC_IKE,
	NM_L2TP_KEY_IPSEC_ESP,
	NM_L2TP_KEY_IPSEC_FORCEENCAPS,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &ipsec_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;
		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
ipsec_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVpn *s_vpn;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = nm_connection_get_setting_vpn (connection);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);
	return hash;
}

static void
handle_enable_changed (GtkWidget *check, gboolean is_init, GtkBuilder *builder)
{
	GtkWidget *widget;
	gboolean enabledp;

	enabledp = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "general_label"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_psk"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_gateway_id"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_gateway_id"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_advanced"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "advanced_expander"));
	if (!enabledp)
		gtk_expander_set_expanded (GTK_EXPANDER (widget), FALSE);
	gtk_widget_set_sensitive (widget, enabledp);
}

static void
enable_toggled_cb (GtkWidget *check, gpointer user_data)
{
	handle_enable_changed (check, FALSE, (GtkBuilder *) user_data);
}

GtkWidget *
ipsec_dialog_new (GHashTable *hash)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	GtkWidget *widget;
	const char *value;
	GError *error = NULL;

	g_return_val_if_fail (hash != NULL, NULL);

	builder = gtk_builder_new ();

	if (!gtk_builder_add_from_resource (builder, "/org/freedesktop/network-manager-l2tp/nm-l2tp-dialog.ui", &error)) {
		g_warning ("Couldn't load builder file: %s", error ? error->message
		           : "(unknown)");
		g_clear_error (&error);
		g_object_unref(G_OBJECT(builder));
		return NULL;
	}
	gtk_builder_set_translation_domain(builder, GETTEXT_PACKAGE);

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "l2tp-ipsec-dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		return NULL;
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "gtkbuilder-xml",
			builder, (GDestroyNotify) g_object_unref);

	value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_ENABLE);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_enable"));
	if (value && !strcmp (value, "yes")) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}
	handle_enable_changed (widget, TRUE, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (enable_toggled_cb), builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_gateway_id"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_GATEWAY_ID)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_PSK)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	/* Phase 1 Algorithms: IKE */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_phase1"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_IKE))) {
		gtk_entry_set_text(GTK_ENTRY(widget), value);
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "advanced_expander"));
		gtk_expander_set_expanded (GTK_EXPANDER (widget), TRUE);
	}

	/* Phase 2 Algorithms: ESP */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_phase2"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_ESP)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_FORCEENCAPS);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "forceencaps_enable"));
	if (value && !strcmp (value, "yes")) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
	}

	return dialog;
}

GHashTable *
ipsec_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable *hash;
	GtkWidget *widget;
	GtkBuilder *builder;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "gtkbuilder-xml");
	g_return_val_if_fail (builder != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_enable"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_ENABLE), g_strdup("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_gateway_id"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_GATEWAY_ID),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PSK),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_phase1"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_IKE),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_phase2"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_ESP),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "forceencaps_enable"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_FORCEENCAPS), g_strdup("yes"));

	return hash;
}

