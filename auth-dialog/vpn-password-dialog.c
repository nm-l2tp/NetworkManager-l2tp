/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* vpn-password-dialog.c - A use password prompting dialog widget.
 *
 * The Gnome Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the ree Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The Gnome Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 1999, 2000 Eazel, Inc.
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * Authors: Ramiro Estrugo <ramiro@eazel.com>
 *          Dan Williams <dcbw@redhat.com>
 */

#include <config.h>
#include <gnome-keyring-memory.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include "vpn-password-dialog.h"

G_DEFINE_TYPE (VpnPasswordDialog, vpn_password_dialog, GTK_TYPE_DIALOG)

#define VPN_PASSWORD_DIALOG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                            VPN_TYPE_PASSWORD_DIALOG, \
                                            VpnPasswordDialogPrivate))

typedef struct {
	/* Attributes */
	gboolean show_password;
	gboolean show_password_secondary;
	
	/* Internal widgetry and flags */
	GtkWidget *password_entry;
	GtkWidget *password_entry_secondary;
	GtkWidget *show_passwords_checkbox;

	GtkWidget *table_alignment;
	GtkWidget *table;
	GtkSizeGroup *group;
	
	char *primary_password_label;
	char *secondary_password_label;
} VpnPasswordDialogPrivate;

/* VpnPasswordDialogClass methods */
static void vpn_password_dialog_class_init (VpnPasswordDialogClass *password_dialog_class);
static void vpn_password_dialog_init       (VpnPasswordDialog      *password_dialog);

/* GtkDialog callbacks */
static void dialog_show_callback (GtkWidget *widget, gpointer callback_data);
static void dialog_close_callback (GtkWidget *widget, gpointer callback_data);

static void
finalize (GObject *object)
{
	VpnPasswordDialogPrivate *priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (object);
	
	g_object_unref (priv->password_entry);
	g_object_unref (priv->password_entry_secondary);
	g_object_unref (priv->group);

	g_free (priv->primary_password_label);
	g_free (priv->secondary_password_label);

	G_OBJECT_CLASS (vpn_password_dialog_parent_class)->finalize (object);
}

static void
vpn_password_dialog_class_init (VpnPasswordDialogClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (VpnPasswordDialogPrivate));

	object_class->finalize = finalize;
}

static void
vpn_password_dialog_init (VpnPasswordDialog *dialog)
{
	VpnPasswordDialogPrivate *priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	priv->show_password = TRUE;
	priv->primary_password_label = g_strdup ( _("_Password:") );
	priv->show_password_secondary = TRUE;
	priv->secondary_password_label = g_strdup ( _("_Secondary Password:") );
}

/* GtkDialog callbacks */
static void
dialog_show_callback (GtkWidget *widget, gpointer callback_data)
{
	VpnPasswordDialog *dialog = VPN_PASSWORD_DIALOG (callback_data);
	VpnPasswordDialogPrivate *priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	if (gtk_widget_get_visible (priv->password_entry))
		gtk_widget_grab_focus (priv->password_entry);
	else if (gtk_widget_get_visible (priv->password_entry_secondary))
		gtk_widget_grab_focus (priv->password_entry_secondary);
}

static void
dialog_close_callback (GtkWidget *widget, gpointer callback_data)
{
	gtk_widget_hide (widget);
}

static void
add_row (GtkWidget *table, int row, const char *label_text, GtkWidget *entry)
{
	GtkWidget *label;

	label = gtk_label_new_with_mnemonic (label_text);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);

	gtk_table_attach_defaults (GTK_TABLE (table), label, 0, 1, row, row + 1);
	gtk_table_attach_defaults (GTK_TABLE (table), entry, 1, 2, row, row + 1);

	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);
}

static void
remove_child (GtkWidget *child, GtkWidget *table)
{
	gtk_container_remove (GTK_CONTAINER (table), child);
}

static void
add_table_rows (VpnPasswordDialog *dialog)
{
	VpnPasswordDialogPrivate *priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	int row;
	int offset = 0;

	gtk_alignment_set_padding (GTK_ALIGNMENT (priv->table_alignment), 0, 0, offset, 0);

	/* This will not kill the entries, since they are ref:ed */
	gtk_container_foreach (GTK_CONTAINER (priv->table), (GtkCallback) remove_child, priv->table);
	
	row = 0;
	if (priv->show_password)
		add_row (priv->table, row++, priv->primary_password_label, priv->password_entry);
	if (priv->show_password_secondary)
		add_row (priv->table, row++, priv->secondary_password_label,  priv->password_entry_secondary);

	gtk_table_attach_defaults (GTK_TABLE (priv->table), priv->show_passwords_checkbox, 1, 2, row, row + 1);

	gtk_widget_show_all (priv->table);
}

static void
show_passwords_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	VpnPasswordDialog *dialog = VPN_PASSWORD_DIALOG (user_data);
	VpnPasswordDialogPrivate *priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry), visible);
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry_secondary), visible);
}

/* Public VpnPasswordDialog methods */
GtkWidget *
vpn_password_dialog_new (const char *title,
                         const char *message,
                         const char *password)
{
	GtkWidget *dialog;
	VpnPasswordDialogPrivate *priv;
	GtkLabel *message_label;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *main_vbox;
	GtkWidget *dialog_icon;
	GtkBox *content, *action_area;

	dialog = gtk_widget_new (VPN_TYPE_PASSWORD_DIALOG, NULL);
	if (!dialog)
		return NULL;
	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	gtk_window_set_title (GTK_WINDOW (dialog), title);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);

	gtk_dialog_add_buttons (GTK_DIALOG (dialog),
	                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
	                        GTK_STOCK_OK, GTK_RESPONSE_OK,
	                        NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

	content = GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (dialog)));
	action_area = GTK_BOX (gtk_dialog_get_action_area (GTK_DIALOG (dialog)));

	/* Setup the dialog */
#if !GTK_CHECK_VERSION (2,22,0)
	gtk_dialog_set_has_separator (GTK_DIALOG (dialog), FALSE);
#endif
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 5);
	gtk_box_set_spacing (content, 2); /* 2 * 5 + 2 = 12 */
	gtk_container_set_border_width (GTK_CONTAINER (action_area), 5);
	gtk_box_set_spacing (action_area, 6);

 	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_signal_connect (dialog, "show",
	                  G_CALLBACK (dialog_show_callback),
	                  dialog);
	g_signal_connect (dialog, "close",
	                  G_CALLBACK (dialog_close_callback),
	                  dialog);

	/* The table that holds the captions */
	priv->table_alignment = gtk_alignment_new (0.0, 0.0, 0.0, 0.0);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	priv->table = gtk_table_new (4, 2, FALSE);
	gtk_table_set_col_spacings (GTK_TABLE (priv->table), 12);
	gtk_table_set_row_spacings (GTK_TABLE (priv->table), 6);
	gtk_container_add (GTK_CONTAINER (priv->table_alignment), priv->table);

	priv->password_entry = gtk_entry_new ();
	priv->password_entry_secondary = gtk_entry_new ();

	priv->show_passwords_checkbox = gtk_check_button_new_with_mnemonic (_("Sh_ow passwords"));

	/* We want to hold on to these during the table rearrangement */
	g_object_ref_sink (priv->password_entry);
	g_object_ref_sink (priv->password_entry_secondary);
	g_object_ref_sink (priv->show_passwords_checkbox);
	
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry), FALSE);
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry_secondary), FALSE);

	g_signal_connect_swapped (priv->password_entry, "activate",
	                          G_CALLBACK (gtk_window_activate_default),
	                          dialog);
	g_signal_connect_swapped (priv->password_entry_secondary, "activate",
	                          G_CALLBACK (gtk_window_activate_default),
	                          dialog);

	g_signal_connect (priv->show_passwords_checkbox, "toggled",
	                  G_CALLBACK (show_passwords_toggled_cb),
	                  dialog);

	add_table_rows (VPN_PASSWORD_DIALOG (dialog));

	/* Adds some eye-candy to the dialog */
#if GTK_CHECK_VERSION (3,1,6)
	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
#else
	hbox = gtk_hbox_new (FALSE, 12);
#endif
 	gtk_container_set_border_width (GTK_CONTAINER (hbox), 5);
	dialog_icon = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (dialog_icon), 0.5, 0.0);
	gtk_box_pack_start (GTK_BOX (hbox), dialog_icon, FALSE, FALSE, 0);

	/* Fills the vbox */
#if GTK_CHECK_VERSION (3,1,6)
	main_vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 18);
#else
	main_vbox = gtk_vbox_new (FALSE, 18);
#endif

	if (message) {
		message_label = GTK_LABEL (gtk_label_new (message));
		gtk_label_set_justify (message_label, GTK_JUSTIFY_LEFT);
		gtk_label_set_line_wrap (message_label, TRUE);
		gtk_label_set_max_width_chars (message_label, 35);
		gtk_size_group_add_widget (priv->group, GTK_WIDGET (message_label));
		gtk_box_pack_start (GTK_BOX (main_vbox), GTK_WIDGET (message_label), FALSE, FALSE, 0);
		gtk_size_group_add_widget (priv->group, priv->table_alignment);
	}

#if GTK_CHECK_VERSION (3,1,6)
	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
#else
	vbox = gtk_vbox_new (FALSE, 6);
#endif
	gtk_box_pack_start (GTK_BOX (main_vbox), vbox, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), priv->table_alignment, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (hbox), main_vbox, FALSE, FALSE, 0);
	gtk_box_pack_start (content, hbox, FALSE, FALSE, 0);
	gtk_widget_show_all (GTK_WIDGET (content));

	vpn_password_dialog_set_password (VPN_PASSWORD_DIALOG (dialog), password);
	
	return GTK_WIDGET (dialog);
}

gboolean
vpn_password_dialog_run_and_block (VpnPasswordDialog *dialog)
{
	gint button_clicked;

	g_return_val_if_fail (dialog != NULL, FALSE);
	g_return_val_if_fail (VPN_IS_PASSWORD_DIALOG (dialog), FALSE);

	button_clicked = gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_hide (GTK_WIDGET (dialog));

	return button_clicked == GTK_RESPONSE_OK;
}

void
vpn_password_dialog_set_password (VpnPasswordDialog	*dialog,
                                  const char *password)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gtk_entry_set_text (GTK_ENTRY (priv->password_entry), password ? password : "");
}

void
vpn_password_dialog_set_password_secondary (VpnPasswordDialog *dialog,
                                            const char *password_secondary)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gtk_entry_set_text (GTK_ENTRY (priv->password_entry_secondary),
	                    password_secondary ? password_secondary : "");
}

void
vpn_password_dialog_set_show_password (VpnPasswordDialog *dialog, gboolean show)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	show = !!show;
	if (priv->show_password != show) {
		priv->show_password = show;
		add_table_rows (dialog);
	}
}

void
vpn_password_dialog_set_show_password_secondary (VpnPasswordDialog *dialog,
                                                 gboolean show)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	show = !!show;
	if (priv->show_password_secondary != show) {
		priv->show_password_secondary = show;
		add_table_rows (dialog);
	}
}

void
vpn_password_dialog_focus_password (VpnPasswordDialog *dialog)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	if (priv->show_password)
		gtk_widget_grab_focus (priv->password_entry);
}

void
vpn_password_dialog_focus_password_secondary (VpnPasswordDialog *dialog)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	if (priv->show_password_secondary)
		gtk_widget_grab_focus (priv->password_entry_secondary);
}

const char *
vpn_password_dialog_get_password (VpnPasswordDialog *dialog)
{
	VpnPasswordDialogPrivate *priv;

	g_return_val_if_fail (VPN_IS_PASSWORD_DIALOG (dialog), NULL);

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	return gtk_entry_get_text (GTK_ENTRY (priv->password_entry));
}

const char *
vpn_password_dialog_get_password_secondary (VpnPasswordDialog *dialog)
{
	VpnPasswordDialogPrivate *priv;

	g_return_val_if_fail (VPN_IS_PASSWORD_DIALOG (dialog), NULL);

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	return gtk_entry_get_text (GTK_ENTRY (priv->password_entry_secondary));
}

void vpn_password_dialog_set_password_label (VpnPasswordDialog *dialog,
                                             const char *label)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	g_free (priv->primary_password_label);
	priv->primary_password_label = g_strdup (label);

	if (priv->show_password)
		add_table_rows (dialog);
}

void vpn_password_dialog_set_password_secondary_label (VpnPasswordDialog *dialog,
                                                       const char *label)
{
	VpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (VPN_IS_PASSWORD_DIALOG (dialog));

	priv = VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	g_free (priv->secondary_password_label);
	priv->secondary_password_label = g_strdup (label);

	if (priv->show_password_secondary)
		add_table_rows (dialog);
}

